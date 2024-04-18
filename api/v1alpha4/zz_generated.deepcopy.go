//go:build !ignore_autogenerated

/*
Copyright 2022 Google LLC.
Copyright 2024 Delta10 B.V.

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha4

import (
	"k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainCache) DeepCopyInto(out *DomainCache) {
	*out = *in
	in.NextUpdateTime.DeepCopyInto(&out.NextUpdateTime)
	if in.IPExpiration != nil {
		in, out := &in.IPExpiration, &out.IPExpiration
		*out = make(map[string]metav1.Time, len(*in))
		for key, val := range *in {
			(*out)[key] = *val.DeepCopy()
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainCache.
func (in *DomainCache) DeepCopy() *DomainCache {
	if in == nil {
		return nil
	}
	out := new(DomainCache)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicy) DeepCopyInto(out *FQDNNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicy.
func (in *FQDNNetworkPolicy) DeepCopy() *FQDNNetworkPolicy {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FQDNNetworkPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicyEgressRule) DeepCopyInto(out *FQDNNetworkPolicyEgressRule) {
	*out = *in
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = make([]v1.NetworkPolicyPort, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.To != nil {
		in, out := &in.To, &out.To
		*out = make([]FQDNNetworkPolicyPeer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicyEgressRule.
func (in *FQDNNetworkPolicyEgressRule) DeepCopy() *FQDNNetworkPolicyEgressRule {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicyEgressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicyIngressRule) DeepCopyInto(out *FQDNNetworkPolicyIngressRule) {
	*out = *in
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = make([]v1.NetworkPolicyPort, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.From != nil {
		in, out := &in.From, &out.From
		*out = make([]FQDNNetworkPolicyPeer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicyIngressRule.
func (in *FQDNNetworkPolicyIngressRule) DeepCopy() *FQDNNetworkPolicyIngressRule {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicyIngressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicyList) DeepCopyInto(out *FQDNNetworkPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]FQDNNetworkPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicyList.
func (in *FQDNNetworkPolicyList) DeepCopy() *FQDNNetworkPolicyList {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FQDNNetworkPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicyPeer) DeepCopyInto(out *FQDNNetworkPolicyPeer) {
	*out = *in
	if in.FQDNs != nil {
		in, out := &in.FQDNs, &out.FQDNs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicyPeer.
func (in *FQDNNetworkPolicyPeer) DeepCopy() *FQDNNetworkPolicyPeer {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicyPeer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicySpec) DeepCopyInto(out *FQDNNetworkPolicySpec) {
	*out = *in
	in.PodSelector.DeepCopyInto(&out.PodSelector)
	if in.Ingress != nil {
		in, out := &in.Ingress, &out.Ingress
		*out = make([]FQDNNetworkPolicyIngressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Egress != nil {
		in, out := &in.Egress, &out.Egress
		*out = make([]FQDNNetworkPolicyEgressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.PolicyTypes != nil {
		in, out := &in.PolicyTypes, &out.PolicyTypes
		*out = make([]v1.PolicyType, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicySpec.
func (in *FQDNNetworkPolicySpec) DeepCopy() *FQDNNetworkPolicySpec {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicyStatus) DeepCopyInto(out *FQDNNetworkPolicyStatus) {
	*out = *in
	if in.LastSyncTime != nil {
		in, out := &in.LastSyncTime, &out.LastSyncTime
		*out = (*in).DeepCopy()
	}
	if in.NextSyncTime != nil {
		in, out := &in.NextSyncTime, &out.NextSyncTime
		*out = (*in).DeepCopy()
	}
	if in.Cache != nil {
		in, out := &in.Cache, &out.Cache
		*out = make(map[string]DomainCache, len(*in))
		for key, val := range *in {
			(*out)[key] = *val.DeepCopy()
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicyStatus.
func (in *FQDNNetworkPolicyStatus) DeepCopy() *FQDNNetworkPolicyStatus {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicyStatus)
	in.DeepCopyInto(out)
	return out
}