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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	NextSyncPeriod int
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
// TODO(user): Modify the Reconcile function to compare the state specified by
// the FQDNNetworkPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *FQDNNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
	log := r.Log.WithValues("fqdnnetworkpolicy", req.NamespacedName)

	// TODO(user): your logic here
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

	// Updating the NetworkPolicy associated with our FQDNNetworkPolicy
	// nextSyncIn represents when we should check in again on that FQDNNetworkPolicy.
	// It's probably related to the TTL of the DNS records.
	nextSyncIn, err := r.updateNetworkPolicy(ctx, fqdnNetworkPolicy)
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
	log.Info("NetworkPolicy updated, next sync in " + fmt.Sprint(nextSyncIn))

	// Need to fetch the object again before updating it
	// as its status may have changed since the first time
	// we fetched it.
	if err := r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      req.Name,
	}, fqdnNetworkPolicy); err != nil {
		log.Error(err, "unable to fetch FQDNNetworkPolicy")
		return ctrl.Result{}, err
	}

	fqdnNetworkPolicy.Status.State = networkingv1alpha4.ActiveState
	nextSyncTime := metav1.NewTime(time.Now().Add(*nextSyncIn))
	fqdnNetworkPolicy.Status.NextSyncTime = &nextSyncTime

	// Updating the status of our FQDNNetworkPolicy
	if err := r.Status().Update(ctx, fqdnNetworkPolicy); err != nil {
		log.Error(err, "unable to update FQDNNetworkPolicy status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: *nextSyncIn}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FQDNNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mgr.GetFieldIndexer()
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha4.FQDNNetworkPolicy{}).
		Complete(r)
}

func (r *FQDNNetworkPolicyReconciler) updateNetworkPolicy(ctx context.Context,
	fqdnNetworkPolicy *networkingv1alpha4.FQDNNetworkPolicy) (*time.Duration, error) {
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)
	toCreate := false

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
	if networkPolicy.Annotations == nil {
		networkPolicy.Annotations = make(map[string]string)
	}
	networkPolicy.Spec.PodSelector = fqdnNetworkPolicy.Spec.PodSelector
	networkPolicy.Spec.PolicyTypes = fqdnNetworkPolicy.Spec.PolicyTypes
	// egress rules
	egressRules, nextSync, err := r.getNetworkPolicyEgressRules(ctx, fqdnNetworkPolicy)
	if err != nil {
		return nil, err
	}
	networkPolicy.Spec.Egress = egressRules
	// ingress rules
	ingressRules, ingressNextSync, err := r.getNetworkPolicyIngressRules(ctx, fqdnNetworkPolicy)
	if err != nil {
		return nil, err
	}
	// We sync just after the shortest TTL between ingress and egress rules
	networkPolicy.Spec.Ingress = ingressRules
	if ingressNextSync.Milliseconds() < nextSync.Milliseconds() {
		nextSync = ingressNextSync
	}

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
func (r *FQDNNetworkPolicyReconciler) getNetworkPolicyIngressRules(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha4.FQDNNetworkPolicy) ([]networking.NetworkPolicyIngressRule, *time.Duration, error) {
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)
	fir := fqdnNetworkPolicy.Spec.Ingress
	rules := []networking.NetworkPolicyIngressRule{}

	// getting the nameservers from the local /etc/resolv.conf
	ns, err := getNameservers()
	if err != nil {
		log.Error(err, "unable to get nameservers")
		return nil, nil, err
	}
	var nextSync uint32
	// Highest value possible for the resync time on the FQDNNetworkPolicy
	// TODO what should this be?
	nextSync = uint32(r.Config.NextSyncPeriod)

	// TODO what do we do if nothing resolves, or if the list is empty?
	// What's the behavior of NetworkPolicies in that case?
	for _, frule := range fir {
		peers := []networking.NetworkPolicyPeer{}
		for _, from := range frule.From {
			for _, fqdn := range from.FQDNs {
				f := fqdn
				// The FQDN in the DNS request needs to end by a dot
				if l := fqdn[len(fqdn)-1]; l != '.' {
					f = fqdn + "."
				}
				c := new(dns.Client)
				c.SingleInflight = true

				// A records
				m := new(dns.Msg)
				m.SetQuestion(f, dns.TypeA)

				// TODO: We're always using the first nameserver. Should we do
				// something different? Note from Jens:
				// by default only if options rotate is set in resolv.conf
				// they are rotated. Otherwise the first is used, after a (5s)
				// timeout the next etc. So this is not too bad for now.
				r, _, err := c.Exchange(m, "["+ns[0]+"]:53")
				if err != nil {
					log.Error(err, "unable to resolve "+f)
					continue
				}
				if len(r.Answer) == 0 {
					log.V(1).Info("could not find A record for " + f)
				}
				for _, ans := range r.Answer {
					if t, ok := ans.(*dns.A); ok {
						// Adding a peer per answer
						peers = append(peers, networking.NetworkPolicyPeer{
							IPBlock: &networking.IPBlock{CIDR: t.A.String() + "/32"}})
						// We want the next sync for the FQDNNetworkPolicy to happen
						// just after the TTL of the DNS record has expired.
						// Because a single FQDNNetworkPolicy may have different DNS
						// records with different TTLs, we pick the lowest one
						// and resynchronise after that.
						if ans.Header().Ttl < nextSync {
							nextSync = ans.Header().Ttl
						}
					}
				}

				// AAAA records
				m6 := new(dns.Msg)
				m6.SetQuestion(f, dns.TypeAAAA)

				// TODO: We're always using the first nameserver. Should we do
				// something different? Note from Jens:
				// by default only if options rotate is set in resolv.conf
				// they are rotated. Otherwise the first is used, after a (5s)
				// timeout the next etc. So this is not too bad for now.
				r6, _, err := c.Exchange(m6, "["+ns[0]+"]:53")
				if err != nil {
					log.Error(err, "unable to resolve "+f)
					continue
				}
				if len(r6.Answer) == 0 {
					log.V(1).Info("could not find AAAA record for " + f)
				}
				for _, ans := range r6.Answer {
					if t, ok := ans.(*dns.AAAA); ok {
						// Adding a peer per answer
						peers = append(peers, networking.NetworkPolicyPeer{
							IPBlock: &networking.IPBlock{CIDR: t.AAAA.String() + "/128"}})
						// We want the next sync for the FQDNNetworkPolicy to happen
						// just after the TTL of the DNS record has expired.
						// Because a single FQDNNetworkPolicy may have different DNS
						// records with different TTLs, we pick the lowest one
						// and resynchronise after that.
						if ans.Header().Ttl < nextSync {
							nextSync = ans.Header().Ttl
						}
					}
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
	}

	n := time.Second * time.Duration(nextSync)

	return rules, &n, nil
}

// getNetworkPolicyEgressRules returns a slice of NetworkPolicyEgressRules based on the
// provided slice of FQDNNetworkPolicyEgressRules, also returns when the next sync should happen
// based on the TTL of records
func (r *FQDNNetworkPolicyReconciler) getNetworkPolicyEgressRules(ctx context.Context, fqdnNetworkPolicy *networkingv1alpha4.FQDNNetworkPolicy) ([]networking.NetworkPolicyEgressRule, *time.Duration, error) {
	log := r.Log.WithValues("fqdnnetworkpolicy", fqdnNetworkPolicy.Namespace+"/"+fqdnNetworkPolicy.Name)
	fer := fqdnNetworkPolicy.Spec.Egress
	rules := []networking.NetworkPolicyEgressRule{}

	// getting the nameservers from the local /etc/resolv.conf
	ns, err := getNameservers()
	if err != nil {
		log.Error(err, "unable to get nameservers")
		return nil, nil, err
	}
	var nextSync uint32
	// Highest value possible for the resync time on the FQDNNetworkPolicy
	// TODO what should this be?
	nextSync = uint32(r.Config.NextSyncPeriod)

	// TODO what do we do if nothing resolves, or if the list is empty?
	// What's the behavior of NetworkPolicies in that case?
	for _, frule := range fer {
		peers := []networking.NetworkPolicyPeer{}
		for _, to := range frule.To {
			for _, fqdn := range to.FQDNs {
				f := fqdn
				// The FQDN in the DNS request needs to end by a dot
				if l := fqdn[len(fqdn)-1]; l != '.' {
					f = fqdn + "."
				}
				c := new(dns.Client)
				c.SingleInflight = true

				// A records
				m := new(dns.Msg)
				m.SetQuestion(f, dns.TypeA)

				// TODO: We're always using the first nameserver. Should we do
				// something different? Note from Jens:
				// by default only if options rotate is set in resolv.conf
				// they are rotated. Otherwise the first is used, after a (5s)
				// timeout the next etc. So this is not too bad for now.
				e, _, err := c.Exchange(m, "["+ns[0]+"]:53")
				if err != nil {
					log.Error(err, "unable to resolve "+f)
					continue
				}
				if len(e.Answer) == 0 {
					log.V(1).Info("could not find A record for " + f)
				}
				for _, ans := range e.Answer {
					if t, ok := ans.(*dns.A); ok {
						// Adding a peer per answer
						peers = append(peers, networking.NetworkPolicyPeer{
							IPBlock: &networking.IPBlock{CIDR: t.A.String() + "/32"}})
						// We want the next sync for the FQDNNetworkPolicy to happen
						// just after the TTL of the DNS record has expired.
						// Because a single FQDNNetworkPolicy may have different DNS
						// records with different TTLs, we pick the lowest one
						// and resynchronise after that.
						if ans.Header().Ttl < nextSync {
							nextSync = ans.Header().Ttl
						}
					}
				}
				// check for AAAA lookups skip annotation
				if fqdnNetworkPolicy.Annotations[aaaaLookupsAnnotation] == "skip" || r.Config.SkipAAAA {
					log.Info("FQDNNetworkPolicy has AAAA lookups policy set to skip, not resolving AAAA records")
				} else {
					// AAAA records
					m6 := new(dns.Msg)
					m6.SetQuestion(f, dns.TypeAAAA)

					// TODO: We're always using the first nameserver. Should we do
					// something different? Note from Jens:
					// by default only if options rotate is set in resolv.conf
					// they are rotated. Otherwise the first is used, after a (5s)
					// timeout the next etc. So this is not too bad for now.
					r6, _, err := c.Exchange(m6, "["+ns[0]+"]:53")
					if err != nil {
						log.Error(err, "unable to resolve "+f)
						continue
					}
					if len(r6.Answer) == 0 {
						log.V(1).Info("could not find AAAA record for " + f)
					}
					for _, ans := range r6.Answer {
						if t, ok := ans.(*dns.AAAA); ok {
							// Adding a peer per answer
							peers = append(peers, networking.NetworkPolicyPeer{
								IPBlock: &networking.IPBlock{CIDR: t.AAAA.String() + "/128"}})
							// We want the next sync for the FQDNNetworkPolicy to happen
							// just after the TTL of the DNS record has expired.
							// Because a single FQDNNetworkPolicy may have different DNS
							// records with different TTLs, we pick the lowest one
							// and resynchronise after that.
							if ans.Header().Ttl < nextSync {
								nextSync = ans.Header().Ttl
							}
						}
					}
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
	}

	n := time.Second * time.Duration(nextSync)

	return rules, &n, nil
}
