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
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	networkingv1alpha4 "github.com/delta10/fqdnnetworkpolicies/api/v1alpha4"

	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	TIMEOUT      = time.Millisecond * time.Duration(3000)
	POLLINTERVAL = time.Millisecond * time.Duration(200)
)

var _ = Describe("FQDNNetworkPolicy controller", func() {
	SetDefaultEventuallyTimeout(TIMEOUT)
	SetDefaultEventuallyPollingInterval(POLLINTERVAL)

	Describe("Creating a FQDNNetworkPolicy", func() {
		Context("when the NetworkPolicy doesn't exist beforehand", func() {
			ctx := context.Background()
			It("Should create a NetworkPolicy of the same name with the correct CIDRs", func() {
				fqdnNetworkPolicy := getFQDNNetworkPolicy("context1", "default")
				nn := types.NamespacedName{
					Namespace: fqdnNetworkPolicy.Namespace,
					Name:      fqdnNetworkPolicy.Name,
				}
				now := time.Now()
				Expect(k8sClient.Create(ctx, &fqdnNetworkPolicy)).Should(Succeed())
				Eventually(func() error {
					r := net.Resolver{}
					// computing the expected IPs in the NetworkPolicy
					// from the FQDNs in the FQDNNetworkPolicy
					// We use a different lib for resolving than the one in the main code
					expectedIPs := []string{}
					for _, fer := range fqdnNetworkPolicy.Spec.Egress {
						for _, to := range fer.To {
							for _, fqdn := range to.FQDNs {
								ip4s, err := r.LookupIP(ctx, "ip4", fqdn)
								if err != nil {
									continuing := false
									derr, ok := err.(*net.DNSError)
									if ok && derr.IsNotFound {
										continuing = true
									}
									aerr, ok := err.(*net.AddrError)
									if ok && aerr.Err == "no suitable address found" {
										continuing = true
									}
									if !continuing {
										return err
									}
								}
								for _, ip := range ip4s {
									expectedIPs = append(expectedIPs, ip.String()+"/32")
								}
								ip6s, err := r.LookupIP(ctx, "ip6", fqdn)
								if err != nil {
									continuing := false
									derr, ok := err.(*net.DNSError)
									if ok && derr.IsNotFound {
										continuing = true
									}
									aerr, ok := err.(*net.AddrError)
									if ok && aerr.Err == "no suitable address found" {
										continuing = true
									}
									if !continuing {
										return err
									}
								}
								for _, ip := range ip6s {
									expectedIPs = append(expectedIPs, ip.String()+"/128")
								}
							}
						}
					}
					// Getting the NetworkPolicy and updated FQDNNetworkPolicy
					err := k8sClient.Get(ctx, nn, &fqdnNetworkPolicy)
					if err != nil {
						return err
					}
					networkPolicy := networking.NetworkPolicy{}
					err = k8sClient.Get(ctx, nn, &networkPolicy)
					if err != nil {
						return err
					}
					tr := true
					expectedOwnerReference := metav1.OwnerReference{
						Kind:               "FQDNNetworkPolicy",
						APIVersion:         networkingv1alpha4.GroupVersion.Group + "/" + networkingv1alpha4.GroupVersion.Version,
						UID:                fqdnNetworkPolicy.ObjectMeta.UID,
						Name:               fqdnNetworkPolicy.Name,
						Controller:         &tr,
						BlockOwnerDeletion: &tr,
					}
					Expect(networkPolicy.OwnerReferences).To(ContainElement(expectedOwnerReference))
					if len(networkPolicy.Spec.PolicyTypes) != 1 ||
						networkPolicy.Spec.PolicyTypes[0] != networking.PolicyTypeEgress {
						return errors.New("Unexpected PolicyType: " + fmt.Sprintf("%v", networkPolicy.Spec.PolicyTypes) +
							". Expected PolicyType: [Egress]")
					}
					total := 0
					for _, egressRule := range networkPolicy.Spec.Egress {
						// checking that every CIDR in the NetworkPolicy
						// is in the expect list of IPs
						total += len(egressRule.To)
						for _, to := range egressRule.To {
							if !containsString(expectedIPs, string(to.IPBlock.CIDR)) {
								return errors.New("Unexpected IP in NetworkPolicy: " + string(to.IPBlock.CIDR) +
									". Expected IPs: " + fmt.Sprint(expectedIPs))
							}
						}
					}
					if total != len(expectedIPs) {
						return errors.New("Some expected IPs are not present in the NetworkPolicy")
					}
					total = 0
					for _, dc := range fqdnNetworkPolicy.Status.Cache {
						for ip, expires := range dc.IPExpiration {
							total += 1
							if !containsString(expectedIPs, ip) {
								return errors.New("Unexpected IP in FQDNNetworkPolicy Cache: " + ip +
									". Expected IPs: " + fmt.Sprint(expectedIPs))
							}
							expiresIn := expires.Sub(now)
							if (expiresIn - time.Hour).Abs() > time.Second*time.Duration(5) {
								return fmt.Errorf("Unexpected IP expiration time: expected 1h; got %v", expiresIn)
							}
						}
					}
					if total != len(expectedIPs) {
						return errors.New("Some expected IPs are not present in the FQDNNetworkPolicy Cache")
					}
					return nil
				}).Should(Succeed())
			})
		})
		Context("with an Ingress policy", func() {
			ctx := context.Background()
			fqdnNetworkPolicy := networkingv1alpha4.FQDNNetworkPolicy{}
			fqdnNetworkPolicy.GetValidIngressResource()
			fqdnNetworkPolicy.Namespace = "default"
			nn := types.NamespacedName{
				Namespace: fqdnNetworkPolicy.Namespace,
				Name:      fqdnNetworkPolicy.Name,
			}
			It("Should create a NetworkPolicy of the same name with an Ingress rule with the correct CIDRs", func() {
				Expect(k8sClient.Create(ctx, &fqdnNetworkPolicy)).Should(Succeed())
				now := time.Now()
				Eventually(func() error {
					r := net.Resolver{}
					// computing the expected IPs in the NetworkPolicy
					// from the FQDNs in the FQDNNetworkPolicy
					// We use a different lib for resolving than the one in the main code
					expectedIPs := []string{}
					for _, fir := range fqdnNetworkPolicy.Spec.Ingress {
						for _, from := range fir.From {
							for _, fqdn := range from.FQDNs {
								ip4s, err := r.LookupIP(ctx, "ip4", fqdn)
								if err != nil {
									continuing := false
									derr, ok := err.(*net.DNSError)
									if ok && derr.IsNotFound {
										continuing = true
									}
									aerr, ok := err.(*net.AddrError)
									if ok && aerr.Err == "no suitable address found" {
										continuing = true
									}
									if !continuing {
										return err
									}
								}
								for _, ip := range ip4s {
									expectedIPs = append(expectedIPs, ip.String()+"/32")
								}
								ip6s, err := r.LookupIP(ctx, "ip6", fqdn)
								if err != nil {
									continuing := false
									derr, ok := err.(*net.DNSError)
									if ok && derr.IsNotFound {
										continuing = true
									}
									aerr, ok := err.(*net.AddrError)
									if ok && aerr.Err == "no suitable address found" {
										continuing = true
									}
									if !continuing {
										return err
									}
								}
								for _, ip := range ip6s {
									expectedIPs = append(expectedIPs, ip.String()+"/128")
								}
							}
						}
					}
					// Getting the NetworkPolicy and updated FQDNNetworkPolicy
					err := k8sClient.Get(ctx, nn, &fqdnNetworkPolicy)
					if err != nil {
						return err
					}
					networkPolicy := networking.NetworkPolicy{}
					err = k8sClient.Get(ctx, nn, &networkPolicy)
					if err != nil {
						return err
					}
					if len(networkPolicy.Spec.PolicyTypes) != 1 ||
						networkPolicy.Spec.PolicyTypes[0] != networking.PolicyTypeIngress {
						return errors.New("Unexpected PolicyType: " + fmt.Sprintf("%v", networkPolicy.Spec.PolicyTypes) +
							". Expected PolicyType: [Ingress]")
					}
					total := 0
					for _, ingressRule := range networkPolicy.Spec.Ingress {
						// checking that every CIDR in the NetworkPolicy
						// is in the expect list of IPs
						total += len(ingressRule.From)
						for _, from := range ingressRule.From {
							// removing the /32 at the end of the CIDR
							if !containsString(expectedIPs, string(from.IPBlock.CIDR)) {
								return errors.New("Unexpected IP in NetworkPolicy: " + string(from.IPBlock.CIDR) +
									". Expected IPs: " + fmt.Sprint(expectedIPs))
							}
						}
					}
					if total != len(expectedIPs) {
						return errors.New("Some expected IPs are not present in the NetworkPolicy")
					}
					total = 0
					for _, dc := range fqdnNetworkPolicy.Status.Cache {
						for ip, expires := range dc.IPExpiration {
							total += 1
							if !containsString(expectedIPs, ip) {
								return errors.New("Unexpected IP in FQDNNetworkPolicy Cache: " + ip +
									". Expected IPs: " + fmt.Sprint(expectedIPs))
							}
							expiresIn := expires.Sub(now)
							if (expiresIn - time.Hour).Abs() > time.Second*time.Duration(5) {
								return fmt.Errorf("Unexpected IP expiration time: expected 1h; got %v", expiresIn)
							}
						}
					}
					if total != len(expectedIPs) {
						return errors.New("Some expected IPs are not present in the FQDNNetworkPolicy Cache")
					}
					return nil
				}).Should(Succeed())
			})
		})
		Context("with a non-existent FQDN", func() {
			ctx := context.Background()
			fqdnNetworkPolicy := networkingv1alpha4.FQDNNetworkPolicy{}
			fqdnNetworkPolicy.GetValidNonExistentFQDNResource()
			fqdnNetworkPolicy.Namespace = "default"
			nn := types.NamespacedName{
				Namespace: fqdnNetworkPolicy.Namespace,
				Name:      fqdnNetworkPolicy.Name,
			}
			It("Should create a NetworkPolicy of the same name with no egress rule", func() {
				Expect(k8sClient.Create(ctx, &fqdnNetworkPolicy)).Should(Succeed())
				Eventually(func() error {
					// Getting the NetworkPolicy
					networkPolicy := networking.NetworkPolicy{}
					err := k8sClient.Get(ctx, nn, &networkPolicy)
					if err != nil {
						return err
					}
					Expect(len(networkPolicy.Spec.Egress)).Should(BeZero())
					return nil
				}).Should(Succeed())
			})
		})
		Context("when a NetworkPolicy with a conflicting controller ownerReference already exists", func() {
			ctx := context.Background()
			fqdnNetworkPolicy := getFQDNNetworkPolicy("context2", "default")
			networkPolicy := getNetworkPolicy(fqdnNetworkPolicy.Name, fqdnNetworkPolicy.Namespace)
			tr := true
			networkPolicy.OwnerReferences = append(
				networkPolicy.OwnerReferences,
				metav1.OwnerReference{
					Kind:       "test",
					Name:       "test",
					UID:        "test",
					APIVersion: "test/v1",
					Controller: &tr,
				},
			)
			nn := types.NamespacedName{
				Namespace: fqdnNetworkPolicy.Namespace,
				Name:      fqdnNetworkPolicy.Name,
			}
			It("Should stay in Pending state", func() {
				Expect(k8sClient.Create(ctx, &networkPolicy)).Should(Succeed())
				Expect(k8sClient.Create(ctx, &fqdnNetworkPolicy)).Should(Succeed())
				time.Sleep(TIMEOUT)
				Expect(k8sClient.Get(ctx, nn, &fqdnNetworkPolicy)).Should(Succeed())
				if fqdnNetworkPolicy.Status.State != networkingv1alpha4.PendingState {
					Fail("FQDNNetworkPolicy should be in pending state. " +
						"State: " + string(fqdnNetworkPolicy.Status.State) + ", " +
						"Reason: " + string(fqdnNetworkPolicy.Status.Reason))
				}
			})
		})
		Context("when a NetworkPolicy with no controller ownerReference already exists and there are some IPs in the FQDNNetworkPolicy cache", func() {
			ctx := context.Background()
			fqdnNetworkPolicy := getFQDNNetworkPolicy("context3", "default")
			networkPolicy := getNetworkPolicy(fqdnNetworkPolicy.Name, fqdnNetworkPolicy.Namespace)
			nn := types.NamespacedName{
				Namespace: fqdnNetworkPolicy.Namespace,
				Name:      fqdnNetworkPolicy.Name,
			}
			domain := fqdnNetworkPolicy.Spec.Egress[0].To[0].FQDNs[0]
			It("Should adopt the NetworkPolicy and be in the Active state", func() {
				Expect(k8sClient.Create(ctx, &networkPolicy)).Should(Succeed())
				Expect(k8sClient.Create(ctx, &fqdnNetworkPolicy)).Should(Succeed())
				time.Sleep(TIMEOUT)
				Expect(k8sClient.Get(ctx, nn, &fqdnNetworkPolicy)).Should(Succeed())
				nextSync := metav1.NewTime(time.Now().Add(-time.Minute))
				fqdnNetworkPolicy.Status.Cache = map[string]*networkingv1alpha4.DomainCache{
					domain: {
						NextUpdateTime: nextSync,
						IPExpiration: map[string]metav1.Time{
							"10.0.0.1/32":  metav1.NewTime(time.Now().Add(time.Minute)),
							"::1/128":      metav1.NewTime(time.Now().Add(time.Minute)),
							"127.0.0.1/32": metav1.NewTime(time.Now().Add(-time.Minute)), // expired
						},
					},
				}
				fqdnNetworkPolicy.Status.NextSyncTime = &nextSync
				Expect(k8sClient.Status().Update(ctx, &fqdnNetworkPolicy)).Should(Succeed())
				Expect(k8sClient.Get(ctx, nn, &fqdnNetworkPolicy)).Should(Succeed())
				time.Sleep(TIMEOUT)

				networkPolicy := networking.NetworkPolicy{}
				Expect(k8sClient.Get(ctx, nn, &networkPolicy)).Should(Succeed())
				tr := true
				expectedOwnerReference := metav1.OwnerReference{
					Kind:               "FQDNNetworkPolicy",
					APIVersion:         networkingv1alpha4.GroupVersion.Group + "/" + networkingv1alpha4.GroupVersion.Version,
					UID:                fqdnNetworkPolicy.ObjectMeta.UID,
					Name:               fqdnNetworkPolicy.Name,
					Controller:         &tr,
					BlockOwnerDeletion: &tr,
				}
				Expect(networkPolicy.OwnerReferences).To(ContainElement(expectedOwnerReference))
				Expect(k8sClient.Get(ctx, nn, &fqdnNetworkPolicy)).Should(Succeed())
				if fqdnNetworkPolicy.Status.State != networkingv1alpha4.ActiveState {
					Fail("FQDNNetworkPolicy should be in active state. " +
						"State: " + string(fqdnNetworkPolicy.Status.State) + ", " +
						"Reason: " + string(fqdnNetworkPolicy.Status.Reason))
				}
				expectedIPsTest := func() error {
					r := net.Resolver{}
					// computing the expected IPs in the NetworkPolicy
					// from the FQDNs in the FQDNNetworkPolicy
					// We use a different lib for resolving than the one in the main code
					expectedIPs := []string{"10.0.0.1/32", "::1/128"}
					for _, fer := range fqdnNetworkPolicy.Spec.Egress {
						for _, from := range fer.To {
							for _, fqdn := range from.FQDNs {
								ip4s, err := r.LookupIP(ctx, "ip4", fqdn)
								if err != nil {
									continuing := false
									derr, ok := err.(*net.DNSError)
									if ok && derr.IsNotFound {
										continuing = true
									}
									aerr, ok := err.(*net.AddrError)
									if ok && aerr.Err == "no suitable address found" {
										continuing = true
									}
									if !continuing {
										return err
									}
								}
								for _, ip := range ip4s {
									expectedIPs = append(expectedIPs, ip.String()+"/32")
								}
								ip6s, err := r.LookupIP(ctx, "ip6", fqdn)
								if err != nil {
									continuing := false
									derr, ok := err.(*net.DNSError)
									if ok && derr.IsNotFound {
										continuing = true
									}
									aerr, ok := err.(*net.AddrError)
									if ok && aerr.Err == "no suitable address found" {
										continuing = true
									}
									if !continuing {
										return err
									}
								}
								for _, ip := range ip6s {
									expectedIPs = append(expectedIPs, ip.String()+"/128")
								}
							}
						}
					}
					total := 0
					for _, egressRule := range networkPolicy.Spec.Egress {
						// checking that every CIDR in the NetworkPolicy
						// is in the expect list of IPs
						total += len(egressRule.To)
						for _, to := range egressRule.To {
							if !containsString(expectedIPs, string(to.IPBlock.CIDR)) {
								return errors.New("Unexpected IP in NetworkPolicy: " + string(to.IPBlock.CIDR) +
									". Expected IPs: " + fmt.Sprint(expectedIPs))
							}
						}
					}
					if total != len(expectedIPs) {
						return errors.New("Some expected IPs are not present in the NetworkPolicy.")
					}
					total = 0
					for _, dc := range fqdnNetworkPolicy.Status.Cache {
						for ip := range dc.IPExpiration {
							total += 1
							if !containsString(expectedIPs, ip) {
								return errors.New("Unexpected IP in FQDNNetworkPolicy Cache: " + ip +
									". Expected IPs: " + fmt.Sprint(expectedIPs))
							}
						}
					}
					if total != len(expectedIPs) {
						return errors.New("Some expected IPs are not present in the FQDNNetworkPolicy Cache")
					}
					return nil
				}
				Expect(expectedIPsTest()).Should(Succeed())
			})
		})
		Context("when the NetworkPolicy has the aaaa-lookups annotation set to skip", func() {
			ctx := context.Background()
			fqdnNetworkPolicy := getFQDNNetworkPolicy("context5", "default")
			fqdnNetworkPolicy.GetValidAaaaLookupsSkippedResource()

			nn := types.NamespacedName{
				Namespace: fqdnNetworkPolicy.Namespace,
				Name:      fqdnNetworkPolicy.Name,
			}
			It("Shouldn't lookup AAAA records", func() {
				Expect(k8sClient.Create(ctx, &fqdnNetworkPolicy)).Should(Succeed())
				now := time.Now()
				Eventually(func() error {
					networkPolicy := networking.NetworkPolicy{}
					return k8sClient.Get(ctx, nn, &networkPolicy)
				}).Should(Succeed())

				// check only ipv4 adresses are present
				Eventually(func() error {
					r := net.Resolver{}
					// computing the expected IPs in the NetworkPolicy
					// from the FQDNs in the FQDNNetworkPolicy
					// We use a different lib for resolving than the one in the main code
					expectedIPs := []string{}
					for _, fer := range fqdnNetworkPolicy.Spec.Egress {
						for _, to := range fer.To {
							for _, fqdn := range to.FQDNs {
								ip4s, err := r.LookupIP(ctx, "ip4", fqdn)
								if err != nil {
									continuing := false
									derr, ok := err.(*net.DNSError)
									if ok && derr.IsNotFound {
										continuing = true
									}
									aerr, ok := err.(*net.AddrError)
									if ok && aerr.Err == "no suitable address found" {
										continuing = true
									}
									if !continuing {
										return err
									}
								}
								for _, ip := range ip4s {
									expectedIPs = append(expectedIPs, ip.String()+"/32")
								}
							}
						}
					}
					// Getting the NetworkPolicy and updated FQDNNetworkPolicy
					err := k8sClient.Get(ctx, nn, &fqdnNetworkPolicy)
					if err != nil {
						return err
					}
					networkPolicy := networking.NetworkPolicy{}
					err = k8sClient.Get(ctx, nn, &networkPolicy)
					if err != nil {
						return err
					}
					if len(networkPolicy.Spec.PolicyTypes) != 1 ||
						networkPolicy.Spec.PolicyTypes[0] != networking.PolicyTypeEgress {
						return errors.New("Unexpected PolicyType: " + fmt.Sprintf("%v", networkPolicy.Spec.PolicyTypes) +
							". Expected PolicyType: [Egress]")
					}
					total := 0
					for _, egressRule := range networkPolicy.Spec.Egress {
						// checking that every CIDR in the NetworkPolicy
						// is in the expect list of IPs
						total += len(egressRule.To)
						for _, to := range egressRule.To {
							// removing the /32 at the end of the CIDR
							if !containsString(expectedIPs, string(to.IPBlock.CIDR)) {
								return errors.New("Unexpected IP in NetworkPolicy: " + string(to.IPBlock.CIDR) +
									". Expected IPs: " + fmt.Sprint(expectedIPs))
							}
						}
					}
					if total != len(expectedIPs) {
						return errors.New("Some expected IPs are not present in the NetworkPolicy")
					}
					total = 0
					for _, dc := range fqdnNetworkPolicy.Status.Cache {
						for ip, expires := range dc.IPExpiration {
							total += 1
							if !containsString(expectedIPs, ip) {
								return errors.New("Unexpected IP in FQDNNetworkPolicy Cache: " + ip +
									". Expected IPs: " + fmt.Sprint(expectedIPs))
							}
							expiresIn := expires.Sub(now)
							if (expiresIn - time.Hour).Abs() > time.Second*time.Duration(5) {
								return fmt.Errorf("Unexpected IP expiration time: expected 1h; got %v", expiresIn)
							}
						}
					}
					if total != len(expectedIPs) {
						return errors.New("Some expected IPs are not present in the FQDNNetworkPolicy Cache")
					}
					return nil
				}).Should(Succeed())
			})
		})
	})
})

func TestContainsString(t *testing.T) {
	slice := []string{"foo"}
	slice = append(slice, "bar")
	if !containsString(slice, "foo") {
		t.Error("can't find an existing string")
	}
	if containsString(slice, "random") {
		t.Error("can find a non existing string")
	}
}

func TestRemoveString(t *testing.T) {
	slice := []string{"foo"}
	slice = append(slice, "bar")
	slice = removeString(slice, "foo")
	if containsString(slice, "foo") {
		t.Error("string hasn't been removed")
	}
}

func getFQDNNetworkPolicy(name string, namespace string) networkingv1alpha4.FQDNNetworkPolicy {
	fqdnNetworkPolicy := networkingv1alpha4.FQDNNetworkPolicy{}
	fqdnNetworkPolicy.GetValidResource()
	fqdnNetworkPolicy.Name = name
	fqdnNetworkPolicy.Namespace = namespace
	return fqdnNetworkPolicy
}

func getNetworkPolicy(name string, namespace string) networking.NetworkPolicy {
	return networking.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: networking.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress: []networking.NetworkPolicyEgressRule{
				{
					To: []networking.NetworkPolicyPeer{
						{
							IPBlock: &networking.IPBlock{
								CIDR: "192.168.1.1/32",
							},
						},
					},
					Ports: []networking.NetworkPolicyPort{
						{
							Protocol: p(v1.ProtocolTCP),
							Port: &intstr.IntOrString{
								IntVal: 443,
							},
						},
					},
				},
			},
		},
	}
}

func p(p v1.Protocol) *v1.Protocol { return &p }
