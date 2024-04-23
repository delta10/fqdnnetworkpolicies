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

package v1alpha4

import (
	networking "k8s.io/api/networking/v1"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type State string

const (
	// PendingState is the state of the FQDNNetworkPolicy when it's first created
	PendingState State = "Pending"
	// ActiveState is the state of the FQDNNetworkPolicy when the associated NetworkPolicy is created
	ActiveState State = "Active"
)

// FQDNNetworkPolicySpec defines the desired state of FQDNNetworkPolicy
type FQDNNetworkPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	PodSelector metav1.LabelSelector           `json:"podSelector" protobuf:"bytes,1,opt,name=podSelector"`
	Ingress     []FQDNNetworkPolicyIngressRule `json:"ingress,omitempty" protobuf:"bytes,2,rep,name=ingress"`
	Egress      []FQDNNetworkPolicyEgressRule  `json:"egress,omitempty" protobuf:"bytes,3,rep,name=egress"`
	PolicyTypes []v1.PolicyType                `json:"policyTypes,omitempty" protobuf:"bytes,4,rep,name=policyTypes,casttype=PolicyType"`
}

// FQDNNetworkPolicyStatus defines the observed state of FQDNNetworkPolicy
type FQDNNetworkPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	State        State                   `json:"state"`
	Reason       string                  `json:"reason,omitempty"`
	LastSyncTime *metav1.Time            `json:"lastSyncTime,omitempty"`
	NextSyncTime *metav1.Time            `json:"nextSyncTime,omitempty"`
	Cache        map[string]*DomainCache `json:"cache,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// FQDNNetworkPolicy is the Schema for the fqdnnetworkpolicies API
type FQDNNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FQDNNetworkPolicySpec   `json:"spec,omitempty"`
	Status FQDNNetworkPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// FQDNNetworkPolicyList contains a list of FQDNNetworkPolicy
type FQDNNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FQDNNetworkPolicy `json:"items"`
}

// FQDNNetworkPolicyEgressRule describes a particular set of
// traffic that is allowed out of pods matched by a
// FQDNNetworkPolicySpec's podSelector. The traffic must match
// both ports and to.
type FQDNNetworkPolicyEgressRule struct {
	Ports []networking.NetworkPolicyPort `json:"ports,omitempty"`
	To    []FQDNNetworkPolicyPeer        `json:"to"`
}

// FQDNNetworkPolicyIngressRule describes a particular set of
// traffic that is allowed into pods matched by a
// FQDNNetworkPolicySpec's podSelector. The traffic must match
// both ports and from.
type FQDNNetworkPolicyIngressRule struct {
	Ports []networking.NetworkPolicyPort `json:"ports,omitempty"`
	From  []FQDNNetworkPolicyPeer        `json:"from"`
}

// FQDNNetworkPolicyPeer represents a FQDN that the
// FQDNNetworkPolicy allows connections to.
type FQDNNetworkPolicyPeer struct {
	FQDNs []string `json:"fqdns"`
}

// DomainCache keeps track of when a specific domain should be updated and when
// previously resolved IPs should be removed from the NetworkPolicy
type DomainCache struct {
	NextUpdateTime metav1.Time            `json:"nextUdateTime"`
	IPExpiration   map[string]metav1.Time `json:"ipExpiration"`
}

func init() {
	SchemeBuilder.Register(&FQDNNetworkPolicy{}, &FQDNNetworkPolicyList{})
}
