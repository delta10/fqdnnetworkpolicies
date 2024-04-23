/*
Copyright 2022 Google LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	networkingv1alpha4 "github.com/delta10/fqdnnetworkpolicies/api/v1alpha4"
	"github.com/go-logr/logr"

	"github.com/miekg/dns"
	networking "k8s.io/api/networking/v1"
)

// FQDNNetworkPolicyReconciler reconciles a FQDNNetworkPolicy object
type FQDNNetworkPolicyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	Config Config
}

type Config struct {
	SkipAAAA       bool
	MaxRequeueTime uint32
	IPExpiration   time.Duration
	DNSConfig      *dns.ClientConfig
	DNSProtocol    string
	DNSEnvironment string
	DNSService     string
}

var (
	aaaaLookupsAnnotation = "fqdnnetworkpolicies.networking.gke.io/aaaa-lookups"
	finalizerName         = "finalizer.fqdnnetworkpolicies.networking.gke.io"
	// TODO make retry configurable
	retry = time.Second * time.Duration(10)
)

//+kubebuilder:rbac:groups=networking.gke.io,resources=fqdnnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.gke.io,resources=fqdnnetworkpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.gke.io,resources=fqdnnetworkpolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies/status,verbs=get;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// It fetches a FQDNNetworkPolicy and updates a NetworkPolicy with the same name
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *FQDNNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
	log := r.Log.WithValues("fqdnnetworkpolicy", req.NamespacedName)

	// retrieving the FQDNNetworkPolicy on which we are working
	fqdnNetworkPolicy := &networkingv1alpha4.FQDNNetworkPolicy{}
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      req.Name,
	}, fqdnNetworkPolicy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// we'll ignore not-found errors, since they can't be fixed by an immediate
			// requeue (we'll need to wait for a new notification), and we can get them
			// on deleted requests.
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch FQDNNetworkPolicy")
		return ctrl.Result{}, err
	}

	if fqdnNetworkPolicy.Status.NextSyncTime != nil && fqdnNetworkPolicy.Status.NextSyncTime.After(time.Now()) {
		log.Info("FQDNNetworkPolicy not due for resync")
		nextSyncIn := fqdnNetworkPolicy.Status.NextSyncTime.Sub(time.Now())
		return ctrl.Result{RequeueAfter: nextSyncIn}, nil
	}

	// Updating the NetworkPolicy associated with our FQDNNetworkPolicy
	// Also updates the cache of the FQDNNetworkPolicy
	// nextSyncIn represents when we should check in again on that FQDNNetworkPolicy.
	nextSyncTime, err := r.updateNetworkPolicy(ctx, fqdnNetworkPolicy)
	if err != nil {
		log.Error(err, "unable to update NetworkPolicy")
		fqdnNetworkPolicy.Status.State = networkingv1alpha4.PendingState
		fqdnNetworkPolicy.Status.Reason = err.Error()
		n := metav1.NewTime(time.Now().Add(retry))
		fqdnNetworkPolicy.Status.NextSyncTime = &n
		if e := r.Status().Update(ctx, fqdnNetworkPolicy); e != nil {
			log.Error(e, "unable to update FQDNNetworkPolicy status")
			return ctrl.Result{}, e
		}
		return ctrl.Result{RequeueAfter: retry}, nil
	}
	nextSyncIn := nextSyncTime.Sub(time.Now())
	log.Info("NetworkPolicy updated, next sync in " + fmt.Sprint(nextSyncIn))

	// Need to fetch the object again before updating it
	// as its status may have changed since the first time
	// we fetched it.
	clusterfqdnNetworkPolicy := &networkingv1alpha4.FQDNNetworkPolicy{}
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      req.Name,
	}, clusterfqdnNetworkPolicy); err != nil {
		log.Error(err, "unable to fetch FQDNNetworkPolicy")
		return ctrl.Result{}, err
	}

	clusterfqdnNetworkPolicy.Status.State = networkingv1alpha4.ActiveState
	clusterfqdnNetworkPolicy.Status.Reason = ""
	clusterfqdnNetworkPolicy.Status.NextSyncTime = nextSyncTime
	clusterfqdnNetworkPolicy.Status.Cache = fqdnNetworkPolicy.Status.Cache

	// Updating the status of our FQDNNetworkPolicy
	if err := r.Status().Update(ctx, clusterfqdnNetworkPolicy); err != nil {
		log.Error(err, "unable to update FQDNNetworkPolicy status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: nextSyncIn}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FQDNNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mgr.GetFieldIndexer()
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha4.FQDNNetworkPolicy{}).
		Complete(r)
}

func (r *FQDNNetworkPolicyReconciler) updateNetworkPolicy(ctx context.Context,
	fqdnNetworkPolicy *networkingv1alpha4.FQDNNetworkPolicy) (*metav1.Time, error) {
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)
	toCreate := false

	// Retrieve DNS servers if DNSEnvironment is "kubernetes"
	if err := r.updateDNSConfig(ctx); err != nil {
		return nil, err
	}

	// Trying to fetch an existing NetworkPolicy of the same name as our FQDNNetworkPolicy
	networkPolicy := &networking.NetworkPolicy{}
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: fqdnNetworkPolicy.Namespace,
		Name:      fqdnNetworkPolicy.Name,
	}, networkPolicy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// If there is none, that's OK, it means that we just haven't created it yet
			log.V(1).Info("associated NetworkPolicy doesn't exist, creating it")
			toCreate = true
		} else {
			return nil, err
		}
	}
	if !toCreate {
		log.V(2).Info("Found NetworkPolicy")
	}

	// Updating NetworkPolicy
	networkPolicy.Name = fqdnNetworkPolicy.Name
	networkPolicy.Namespace = fqdnNetworkPolicy.Namespace
	// Set ownerReference. This will faill if the NP is already owned by another controller
	if err := controllerutil.SetControllerReference(fqdnNetworkPolicy, networkPolicy, r.Scheme); err != nil {
		return nil, err
	}
	networkPolicy.Spec.PodSelector = fqdnNetworkPolicy.Spec.PodSelector
	networkPolicy.Spec.PolicyTypes = fqdnNetworkPolicy.Spec.PolicyTypes

	// Connect to DNS servers
	conns, err := r.getDNSConns(ctx)
	defer closeDNSConns(conns)
	if err != nil {
		return nil, err
	}
	r.Log.V(1).Info("Connected to " + strconv.Itoa(len(conns)) + " DNS servers")

	// egress rules
	egressRules, nextSync, caches1, err := r.getNetworkPolicyEgressRules(ctx, fqdnNetworkPolicy, conns)
	if err != nil {
		return nil, err
	}
	networkPolicy.Spec.Egress = egressRules
	// ingress rules
	ingressRules, ingressNextSync, caches2, err := r.getNetworkPolicyIngressRules(ctx, fqdnNetworkPolicy, conns)
	if err != nil {
		return nil, err
	}
	// We sync just after the shortest TTL between ingress and egress rules
	networkPolicy.Spec.Ingress = ingressRules
	if ingressNextSync.Before(nextSync) {
		nextSync = ingressNextSync
	}

	// Merge all caches generated by the rule evaluations
	newCaches := append(caches1, caches2...)
	fqdnNetworkPolicy.Status.Cache = mergeCaches(newCaches...)

	// creating NetworkPolicy if needed
	if toCreate {
		if err := r.Create(ctx, networkPolicy); err != nil {
			log.Error(err, "unable to create NetworkPolicy")
			return nil, err
		}
	}
	// Updating the NetworkPolicy
	if err := r.Update(ctx, networkPolicy); err != nil {
		log.Error(err, "unable to update NetworkPolicy")
		return nil, err
	}

	return nextSync, nil
}

// getNetworkPolicyIngressRules returns a slice of NetworkPolicyIngressRules based on the
// provided slice of FQDNNetworkPolicyIngressRules, also returns when the next sync should happen
// based on the TTL of records
func (r *FQDNNetworkPolicyReconciler) getNetworkPolicyIngressRules(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha4.FQDNNetworkPolicy, conns []*dns.Conn) ([]networking.NetworkPolicyIngressRule, *metav1.Time, []map[string]*networkingv1alpha4.DomainCache, error) {
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)
	fir := fqdnNetworkPolicy.Spec.Ingress
	rules := []networking.NetworkPolicyIngressRule{}

	nextSync := metav1.NewTime(time.Now().Add(time.Second * time.Duration(r.Config.MaxRequeueTime)))
	domainCaches := make([]map[string]*networkingv1alpha4.DomainCache, len(conns)*len(fir))

	for _, frule := range fir {
		results := make([][]networking.NetworkPolicyPeer, len(conns))
		caches := make([]map[string]*networkingv1alpha4.DomainCache, len(conns))
		var wg = sync.WaitGroup{}
		for n, conn := range conns {
			caches[n] = make(map[string]*networkingv1alpha4.DomainCache)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, to := range frule.From {
					for _, f := range to.FQDNs {
						var domainResults []networking.NetworkPolicyPeer
						domainResults, caches[n][f] = r.resolveRule(conn, fqdnNetworkPolicy, f)
						results[n] = append(results[n], domainResults...)
					}
				}
			}()
		}
		wg.Wait()

		peers := flatten(results)
		for _, cc := range caches {
			for _, cache := range cc {
				if cache.NextUpdateTime.Before(&nextSync) {
					nextSync = cache.NextUpdateTime
				}
			}
		}

		if len(peers) == 0 {
			// If no peers have been found (most likely because the provided
			// FQDNs don't resolve to anything), then we don't create an ingress
			// rule at all to fail close. If we create one with only a "ports"
			// section, but no "to" section, we're failing open.
			log.V(1).Info("No peers found, skipping ingress rule.")
			continue
		}

		rules = append(rules, networking.NetworkPolicyIngressRule{
			Ports: frule.Ports,
			From:  peers,
		})
		domainCaches = append(domainCaches, caches...)
	}

	return rules, &nextSync, domainCaches, nil
}

// getNetworkPolicyEgressRules returns a slice of NetworkPolicyEgressRules based on the
// provided slice of FQDNNetworkPolicyEgressRules, also returns when the next sync should happen
// based on the TTL of records
func (r *FQDNNetworkPolicyReconciler) getNetworkPolicyEgressRules(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha4.FQDNNetworkPolicy, conns []*dns.Conn) ([]networking.NetworkPolicyEgressRule, *metav1.Time, []map[string]*networkingv1alpha4.DomainCache, error) {
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)
	fer := fqdnNetworkPolicy.Spec.Egress
	rules := []networking.NetworkPolicyEgressRule{}

	nextSync := metav1.NewTime(time.Now().Add(time.Second * time.Duration(r.Config.MaxRequeueTime)))
	domainCaches := make([]map[string]*networkingv1alpha4.DomainCache, len(conns)*len(fer))

	for _, frule := range fer {
		results := make([][]networking.NetworkPolicyPeer, len(conns))
		caches := make([]map[string]*networkingv1alpha4.DomainCache, len(conns))
		var wg = sync.WaitGroup{}
		for n, conn := range conns {
			caches[n] = make(map[string]*networkingv1alpha4.DomainCache)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, to := range frule.To {
					for _, f := range to.FQDNs {
						var domainResults []networking.NetworkPolicyPeer
						domainResults, caches[n][f] = r.resolveRule(conn, fqdnNetworkPolicy, f)
						results[n] = append(results[n], domainResults...)
					}
				}
			}()
		}
		wg.Wait()

		peers := flatten(results)
		for _, cc := range caches {
			for _, cache := range cc {
				if cache.NextUpdateTime.Before(&nextSync) {
					nextSync = cache.NextUpdateTime
				}
			}
		}

		if len(peers) == 0 {
			// If no peers have been found (most likely because the provided
			// FQDNs don't resolve to anything), then we don't create an egress
			// rule at all to fail close. If we create one with only a "ports"
			// section, but no "to" section, we're failing open.
			log.V(1).Info("No peers found, skipping egress rule.")
			continue
		}

		rules = append(rules, networking.NetworkPolicyEgressRule{
			Ports: frule.Ports,
			To:    peers,
		})
		domainCaches = append(domainCaches, caches...)
	}

	return rules, &nextSync, domainCaches, nil
}

func (r *FQDNNetworkPolicyReconciler) getDNSConns(ctx context.Context) (conns []*dns.Conn, err error) {
	c := new(dns.Client)
	c.Net = r.Config.DNSProtocol
	config := r.Config.DNSConfig
	if config == nil {
		return nil, fmt.Errorf("no DNS configuration found")
	}
	for _, server := range config.Servers {
		conn, err := c.DialContext(ctx, server + ":" + config.Port)
		if err != nil {
			return conns, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func closeDNSConns(conns []*dns.Conn) (err error) {
	for _, conn := range conns {
		err = conn.Close()
	}
	return err
}

func (r *FQDNNetworkPolicyReconciler) resolveRule(conn *dns.Conn, fqdnNetworkPolicy *networkingv1alpha4.FQDNNetworkPolicy, fqdn string) (peers []networking.NetworkPolicyPeer, cache *networkingv1alpha4.DomainCache) {
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)
	conn.SetDeadline(time.Now().Add(time.Second*time.Duration(r.Config.DNSConfig.Timeout)))
	nextSync := r.Config.MaxRequeueTime
	f := fqdn
	cache = &networkingv1alpha4.DomainCache{
		IPExpiration: make(map[string]metav1.Time),
		NextUpdateTime: metav1.NewTime(time.Now().Add(time.Second * time.Duration(nextSync))),
	}
	oldCache, oldCacheExists := fqdnNetworkPolicy.Status.Cache[f]
	if oldCacheExists {
		for ip, expires := range oldCache.IPExpiration {
			if oldCache.NextUpdateTime.After(time.Now()) || expires.After(time.Now()) {
				peers = append(peers, networking.NetworkPolicyPeer{
					IPBlock: &networking.IPBlock{CIDR: ip},
				})
				cache.IPExpiration[ip] = expires
			}
		}
		if oldCache.NextUpdateTime.After(time.Now()) {
			cache.NextUpdateTime = oldCache.NextUpdateTime
			return
		}
	}
	// The FQDN in the DNS request needs to end by a dot
	if l := fqdn[len(fqdn)-1]; l != '.' {
		f = fqdn + "."
	}

	// A records
	m := new(dns.Msg)
	m.SetQuestion(f, dns.TypeA)

	err := conn.WriteMsg(m)
	if err != nil {
		log.Error(err, "unable to resolve "+f)
		return
	}
	e, err := conn.ReadMsg()
	if err != nil {
		log.Error(err, "unable to resolve "+f)
		return
	}
	if len(e.Answer) == 0 {
		log.V(1).Info("could not find A record for " + f)
	}
	for _, ans := range e.Answer {
		if t, ok := ans.(*dns.A); ok {
			// Adding a peer per answer
			cidr := t.A.String() + "/32"
			peers = append(peers, networking.NetworkPolicyPeer{
				IPBlock: &networking.IPBlock{CIDR: cidr}})
			// We want the next sync for the domain to happen
			// just after the TTL of the DNS record has expired.
			if ans.Header().Ttl < nextSync {
				nextSync = ans.Header().Ttl
				if nextSync == 0 {
					log.Info("WARNING: received TTL of zero", "domain", fqdn)
				}
			}
			cache.IPExpiration[cidr] = metav1.NewTime(time.Now().Add(r.Config.IPExpiration))
		}
	}
	// check for AAAA lookups skip annotation
	if fqdnNetworkPolicy.Annotations[aaaaLookupsAnnotation] == "skip" || r.Config.SkipAAAA {
		log.V(1).Info("FQDNNetworkPolicy has AAAA lookups policy set to skip, not resolving AAAA records")
	} else {
		// AAAA records
		m6 := new(dns.Msg)
		m6.SetQuestion(f, dns.TypeAAAA)

		// TODO: We're always using the first nameserver. Should we do
		// something different? Note from Jens:
		// by default only if options rotate is set in resolv.conf
		// they are rotated. Otherwise the first is used, after a (5s)
		// timeout the next etc. So this is not too bad for now.
		err := conn.WriteMsg(m6)
		if err != nil {
			log.Error(err, "unable to resolve "+f)
			return
		}
		r6, err := conn.ReadMsg()
		if err != nil {
			log.Error(err, "unable to resolve "+f)
			return
		}
		if len(r6.Answer) == 0 {
			log.V(1).Info("could not find AAAA record for " + f)
		}
		for _, ans := range r6.Answer {
			if t, ok := ans.(*dns.AAAA); ok {
				// Adding a peer per answer
				cidr := t.AAAA.String() + "/128"
				peers = append(peers, networking.NetworkPolicyPeer{
					IPBlock: &networking.IPBlock{CIDR: cidr}})
				// We want the next sync for the domain to happen
				// just after the TTL of the DNS record has expired.
				// Because a single FQDNNetworkPolicy may have different DNS
				// records with different TTLs, we pick the lowest one
				// and resynchronise after that.
				if ans.Header().Ttl < nextSync {
					nextSync = ans.Header().Ttl
				}
				cache.IPExpiration[cidr] = metav1.NewTime(time.Now().Add(r.Config.IPExpiration))
			}
		}
	}

	// Domain should be updated again 0.5 second after the lowest TTL expires
	cache.NextUpdateTime = metav1.NewTime(
		time.Now().Add(time.Second * time.Duration(nextSync)).Add(time.Millisecond * time.Duration(500)),
	)

	return peers, cache
}

func (r *FQDNNetworkPolicyReconciler) updateDNSConfig(ctx context.Context) error {
	if r.Config.DNSEnvironment != "kubernetes" {
		return nil
	}

	r.Config.DNSConfig.Servers = make([]string, 0, 2)

	// Obtain the pod IPs of kube-dns
	kube_dns_name := types.NamespacedName{
		Namespace: "kube-system",
		Name:      r.Config.DNSService,
	}
	dns_ep := new(v1.Endpoints)
	err := r.Get(ctx, kube_dns_name, dns_ep)
	if err != nil {
		return fmt.Errorf("unable to fetch kube-dns Endpoints: %w", err)
	}
	for i := range dns_ep.Subsets {
		for _, addr := range dns_ep.Subsets[i].Addresses {
			if addr.IP != "" {
				r.Config.DNSConfig.Servers = append(r.Config.DNSConfig.Servers, addr.IP)
			}
		}
	}
	if len(r.Config.DNSConfig.Servers) == 0 {
		return fmt.Errorf("No DNS endpoints found for service %v", r.Config.DNSService)
	}
	return nil
}
