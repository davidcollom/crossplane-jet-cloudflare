//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2021 The Crossplane Authors.

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

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Balancer) DeepCopyInto(out *Balancer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Balancer.
func (in *Balancer) DeepCopy() *Balancer {
	if in == nil {
		return nil
	}
	out := new(Balancer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Balancer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerList) DeepCopyInto(out *BalancerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Balancer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerList.
func (in *BalancerList) DeepCopy() *BalancerList {
	if in == nil {
		return nil
	}
	out := new(BalancerList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BalancerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerMonitor) DeepCopyInto(out *BalancerMonitor) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerMonitor.
func (in *BalancerMonitor) DeepCopy() *BalancerMonitor {
	if in == nil {
		return nil
	}
	out := new(BalancerMonitor)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BalancerMonitor) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerMonitorList) DeepCopyInto(out *BalancerMonitorList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]BalancerMonitor, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerMonitorList.
func (in *BalancerMonitorList) DeepCopy() *BalancerMonitorList {
	if in == nil {
		return nil
	}
	out := new(BalancerMonitorList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BalancerMonitorList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerMonitorObservation) DeepCopyInto(out *BalancerMonitorObservation) {
	*out = *in
	if in.CreatedOn != nil {
		in, out := &in.CreatedOn, &out.CreatedOn
		*out = new(string)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.ModifiedOn != nil {
		in, out := &in.ModifiedOn, &out.ModifiedOn
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerMonitorObservation.
func (in *BalancerMonitorObservation) DeepCopy() *BalancerMonitorObservation {
	if in == nil {
		return nil
	}
	out := new(BalancerMonitorObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerMonitorParameters) DeepCopyInto(out *BalancerMonitorParameters) {
	*out = *in
	if in.AllowInsecure != nil {
		in, out := &in.AllowInsecure, &out.AllowInsecure
		*out = new(bool)
		**out = **in
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.ExpectedBody != nil {
		in, out := &in.ExpectedBody, &out.ExpectedBody
		*out = new(string)
		**out = **in
	}
	if in.ExpectedCodes != nil {
		in, out := &in.ExpectedCodes, &out.ExpectedCodes
		*out = new(string)
		**out = **in
	}
	if in.FollowRedirects != nil {
		in, out := &in.FollowRedirects, &out.FollowRedirects
		*out = new(bool)
		**out = **in
	}
	if in.Header != nil {
		in, out := &in.Header, &out.Header
		*out = make([]HeaderParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Interval != nil {
		in, out := &in.Interval, &out.Interval
		*out = new(float64)
		**out = **in
	}
	if in.Method != nil {
		in, out := &in.Method, &out.Method
		*out = new(string)
		**out = **in
	}
	if in.Path != nil {
		in, out := &in.Path, &out.Path
		*out = new(string)
		**out = **in
	}
	if in.Port != nil {
		in, out := &in.Port, &out.Port
		*out = new(float64)
		**out = **in
	}
	if in.ProbeZone != nil {
		in, out := &in.ProbeZone, &out.ProbeZone
		*out = new(string)
		**out = **in
	}
	if in.Retries != nil {
		in, out := &in.Retries, &out.Retries
		*out = new(float64)
		**out = **in
	}
	if in.Timeout != nil {
		in, out := &in.Timeout, &out.Timeout
		*out = new(float64)
		**out = **in
	}
	if in.Type != nil {
		in, out := &in.Type, &out.Type
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerMonitorParameters.
func (in *BalancerMonitorParameters) DeepCopy() *BalancerMonitorParameters {
	if in == nil {
		return nil
	}
	out := new(BalancerMonitorParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerMonitorSpec) DeepCopyInto(out *BalancerMonitorSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerMonitorSpec.
func (in *BalancerMonitorSpec) DeepCopy() *BalancerMonitorSpec {
	if in == nil {
		return nil
	}
	out := new(BalancerMonitorSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerMonitorStatus) DeepCopyInto(out *BalancerMonitorStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerMonitorStatus.
func (in *BalancerMonitorStatus) DeepCopy() *BalancerMonitorStatus {
	if in == nil {
		return nil
	}
	out := new(BalancerMonitorStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerObservation) DeepCopyInto(out *BalancerObservation) {
	*out = *in
	if in.CreatedOn != nil {
		in, out := &in.CreatedOn, &out.CreatedOn
		*out = new(string)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.ModifiedOn != nil {
		in, out := &in.ModifiedOn, &out.ModifiedOn
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerObservation.
func (in *BalancerObservation) DeepCopy() *BalancerObservation {
	if in == nil {
		return nil
	}
	out := new(BalancerObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerParameters) DeepCopyInto(out *BalancerParameters) {
	*out = *in
	if in.DefaultPoolIds != nil {
		in, out := &in.DefaultPoolIds, &out.DefaultPoolIds
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.Enabled != nil {
		in, out := &in.Enabled, &out.Enabled
		*out = new(bool)
		**out = **in
	}
	if in.FallbackPoolID != nil {
		in, out := &in.FallbackPoolID, &out.FallbackPoolID
		*out = new(string)
		**out = **in
	}
	if in.PopPools != nil {
		in, out := &in.PopPools, &out.PopPools
		*out = make([]PopPoolsParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Proxied != nil {
		in, out := &in.Proxied, &out.Proxied
		*out = new(bool)
		**out = **in
	}
	if in.RegionPools != nil {
		in, out := &in.RegionPools, &out.RegionPools
		*out = make([]RegionPoolsParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]RulesParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.SessionAffinity != nil {
		in, out := &in.SessionAffinity, &out.SessionAffinity
		*out = new(string)
		**out = **in
	}
	if in.SessionAffinityAttributes != nil {
		in, out := &in.SessionAffinityAttributes, &out.SessionAffinityAttributes
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.SessionAffinityTTL != nil {
		in, out := &in.SessionAffinityTTL, &out.SessionAffinityTTL
		*out = new(float64)
		**out = **in
	}
	if in.SteeringPolicy != nil {
		in, out := &in.SteeringPolicy, &out.SteeringPolicy
		*out = new(string)
		**out = **in
	}
	if in.TTL != nil {
		in, out := &in.TTL, &out.TTL
		*out = new(float64)
		**out = **in
	}
	if in.ZoneID != nil {
		in, out := &in.ZoneID, &out.ZoneID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerParameters.
func (in *BalancerParameters) DeepCopy() *BalancerParameters {
	if in == nil {
		return nil
	}
	out := new(BalancerParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerPool) DeepCopyInto(out *BalancerPool) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerPool.
func (in *BalancerPool) DeepCopy() *BalancerPool {
	if in == nil {
		return nil
	}
	out := new(BalancerPool)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BalancerPool) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerPoolList) DeepCopyInto(out *BalancerPoolList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]BalancerPool, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerPoolList.
func (in *BalancerPoolList) DeepCopy() *BalancerPoolList {
	if in == nil {
		return nil
	}
	out := new(BalancerPoolList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BalancerPoolList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerPoolObservation) DeepCopyInto(out *BalancerPoolObservation) {
	*out = *in
	if in.CreatedOn != nil {
		in, out := &in.CreatedOn, &out.CreatedOn
		*out = new(string)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.ModifiedOn != nil {
		in, out := &in.ModifiedOn, &out.ModifiedOn
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerPoolObservation.
func (in *BalancerPoolObservation) DeepCopy() *BalancerPoolObservation {
	if in == nil {
		return nil
	}
	out := new(BalancerPoolObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerPoolParameters) DeepCopyInto(out *BalancerPoolParameters) {
	*out = *in
	if in.CheckRegions != nil {
		in, out := &in.CheckRegions, &out.CheckRegions
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.Enabled != nil {
		in, out := &in.Enabled, &out.Enabled
		*out = new(bool)
		**out = **in
	}
	if in.Latitude != nil {
		in, out := &in.Latitude, &out.Latitude
		*out = new(float64)
		**out = **in
	}
	if in.LoadShedding != nil {
		in, out := &in.LoadShedding, &out.LoadShedding
		*out = make([]LoadSheddingParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Longitude != nil {
		in, out := &in.Longitude, &out.Longitude
		*out = new(float64)
		**out = **in
	}
	if in.MinimumOrigins != nil {
		in, out := &in.MinimumOrigins, &out.MinimumOrigins
		*out = new(float64)
		**out = **in
	}
	if in.Monitor != nil {
		in, out := &in.Monitor, &out.Monitor
		*out = new(string)
		**out = **in
	}
	if in.NotificationEmail != nil {
		in, out := &in.NotificationEmail, &out.NotificationEmail
		*out = new(string)
		**out = **in
	}
	if in.OriginSteering != nil {
		in, out := &in.OriginSteering, &out.OriginSteering
		*out = make([]OriginSteeringParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Origins != nil {
		in, out := &in.Origins, &out.Origins
		*out = make([]OriginsParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerPoolParameters.
func (in *BalancerPoolParameters) DeepCopy() *BalancerPoolParameters {
	if in == nil {
		return nil
	}
	out := new(BalancerPoolParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerPoolSpec) DeepCopyInto(out *BalancerPoolSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerPoolSpec.
func (in *BalancerPoolSpec) DeepCopy() *BalancerPoolSpec {
	if in == nil {
		return nil
	}
	out := new(BalancerPoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerPoolStatus) DeepCopyInto(out *BalancerPoolStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerPoolStatus.
func (in *BalancerPoolStatus) DeepCopy() *BalancerPoolStatus {
	if in == nil {
		return nil
	}
	out := new(BalancerPoolStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerSpec) DeepCopyInto(out *BalancerSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerSpec.
func (in *BalancerSpec) DeepCopy() *BalancerSpec {
	if in == nil {
		return nil
	}
	out := new(BalancerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BalancerStatus) DeepCopyInto(out *BalancerStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BalancerStatus.
func (in *BalancerStatus) DeepCopy() *BalancerStatus {
	if in == nil {
		return nil
	}
	out := new(BalancerStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FixedResponseObservation) DeepCopyInto(out *FixedResponseObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FixedResponseObservation.
func (in *FixedResponseObservation) DeepCopy() *FixedResponseObservation {
	if in == nil {
		return nil
	}
	out := new(FixedResponseObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FixedResponseParameters) DeepCopyInto(out *FixedResponseParameters) {
	*out = *in
	if in.ContentType != nil {
		in, out := &in.ContentType, &out.ContentType
		*out = new(string)
		**out = **in
	}
	if in.Location != nil {
		in, out := &in.Location, &out.Location
		*out = new(string)
		**out = **in
	}
	if in.MessageBody != nil {
		in, out := &in.MessageBody, &out.MessageBody
		*out = new(string)
		**out = **in
	}
	if in.StatusCode != nil {
		in, out := &in.StatusCode, &out.StatusCode
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FixedResponseParameters.
func (in *FixedResponseParameters) DeepCopy() *FixedResponseParameters {
	if in == nil {
		return nil
	}
	out := new(FixedResponseParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HeaderObservation) DeepCopyInto(out *HeaderObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HeaderObservation.
func (in *HeaderObservation) DeepCopy() *HeaderObservation {
	if in == nil {
		return nil
	}
	out := new(HeaderObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HeaderParameters) DeepCopyInto(out *HeaderParameters) {
	*out = *in
	if in.Header != nil {
		in, out := &in.Header, &out.Header
		*out = new(string)
		**out = **in
	}
	if in.Values != nil {
		in, out := &in.Values, &out.Values
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HeaderParameters.
func (in *HeaderParameters) DeepCopy() *HeaderParameters {
	if in == nil {
		return nil
	}
	out := new(HeaderParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LoadSheddingObservation) DeepCopyInto(out *LoadSheddingObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LoadSheddingObservation.
func (in *LoadSheddingObservation) DeepCopy() *LoadSheddingObservation {
	if in == nil {
		return nil
	}
	out := new(LoadSheddingObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LoadSheddingParameters) DeepCopyInto(out *LoadSheddingParameters) {
	*out = *in
	if in.DefaultPercent != nil {
		in, out := &in.DefaultPercent, &out.DefaultPercent
		*out = new(float64)
		**out = **in
	}
	if in.DefaultPolicy != nil {
		in, out := &in.DefaultPolicy, &out.DefaultPolicy
		*out = new(string)
		**out = **in
	}
	if in.SessionPercent != nil {
		in, out := &in.SessionPercent, &out.SessionPercent
		*out = new(float64)
		**out = **in
	}
	if in.SessionPolicy != nil {
		in, out := &in.SessionPolicy, &out.SessionPolicy
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LoadSheddingParameters.
func (in *LoadSheddingParameters) DeepCopy() *LoadSheddingParameters {
	if in == nil {
		return nil
	}
	out := new(LoadSheddingParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OriginSteeringObservation) DeepCopyInto(out *OriginSteeringObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OriginSteeringObservation.
func (in *OriginSteeringObservation) DeepCopy() *OriginSteeringObservation {
	if in == nil {
		return nil
	}
	out := new(OriginSteeringObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OriginSteeringParameters) DeepCopyInto(out *OriginSteeringParameters) {
	*out = *in
	if in.Policy != nil {
		in, out := &in.Policy, &out.Policy
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OriginSteeringParameters.
func (in *OriginSteeringParameters) DeepCopy() *OriginSteeringParameters {
	if in == nil {
		return nil
	}
	out := new(OriginSteeringParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OriginsHeaderObservation) DeepCopyInto(out *OriginsHeaderObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OriginsHeaderObservation.
func (in *OriginsHeaderObservation) DeepCopy() *OriginsHeaderObservation {
	if in == nil {
		return nil
	}
	out := new(OriginsHeaderObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OriginsHeaderParameters) DeepCopyInto(out *OriginsHeaderParameters) {
	*out = *in
	if in.Header != nil {
		in, out := &in.Header, &out.Header
		*out = new(string)
		**out = **in
	}
	if in.Values != nil {
		in, out := &in.Values, &out.Values
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OriginsHeaderParameters.
func (in *OriginsHeaderParameters) DeepCopy() *OriginsHeaderParameters {
	if in == nil {
		return nil
	}
	out := new(OriginsHeaderParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OriginsObservation) DeepCopyInto(out *OriginsObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OriginsObservation.
func (in *OriginsObservation) DeepCopy() *OriginsObservation {
	if in == nil {
		return nil
	}
	out := new(OriginsObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OriginsParameters) DeepCopyInto(out *OriginsParameters) {
	*out = *in
	if in.Address != nil {
		in, out := &in.Address, &out.Address
		*out = new(string)
		**out = **in
	}
	if in.Enabled != nil {
		in, out := &in.Enabled, &out.Enabled
		*out = new(bool)
		**out = **in
	}
	if in.Header != nil {
		in, out := &in.Header, &out.Header
		*out = make([]OriginsHeaderParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
	if in.Weight != nil {
		in, out := &in.Weight, &out.Weight
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OriginsParameters.
func (in *OriginsParameters) DeepCopy() *OriginsParameters {
	if in == nil {
		return nil
	}
	out := new(OriginsParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OverridesObservation) DeepCopyInto(out *OverridesObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OverridesObservation.
func (in *OverridesObservation) DeepCopy() *OverridesObservation {
	if in == nil {
		return nil
	}
	out := new(OverridesObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OverridesParameters) DeepCopyInto(out *OverridesParameters) {
	*out = *in
	if in.DefaultPools != nil {
		in, out := &in.DefaultPools, &out.DefaultPools
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
	if in.FallbackPool != nil {
		in, out := &in.FallbackPool, &out.FallbackPool
		*out = new(string)
		**out = **in
	}
	if in.PopPools != nil {
		in, out := &in.PopPools, &out.PopPools
		*out = make([]OverridesPopPoolsParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.RegionPools != nil {
		in, out := &in.RegionPools, &out.RegionPools
		*out = make([]OverridesRegionPoolsParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.SessionAffinity != nil {
		in, out := &in.SessionAffinity, &out.SessionAffinity
		*out = new(string)
		**out = **in
	}
	if in.SessionAffinityAttributes != nil {
		in, out := &in.SessionAffinityAttributes, &out.SessionAffinityAttributes
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.SessionAffinityTTL != nil {
		in, out := &in.SessionAffinityTTL, &out.SessionAffinityTTL
		*out = new(float64)
		**out = **in
	}
	if in.SteeringPolicy != nil {
		in, out := &in.SteeringPolicy, &out.SteeringPolicy
		*out = new(string)
		**out = **in
	}
	if in.TTL != nil {
		in, out := &in.TTL, &out.TTL
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OverridesParameters.
func (in *OverridesParameters) DeepCopy() *OverridesParameters {
	if in == nil {
		return nil
	}
	out := new(OverridesParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OverridesPopPoolsObservation) DeepCopyInto(out *OverridesPopPoolsObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OverridesPopPoolsObservation.
func (in *OverridesPopPoolsObservation) DeepCopy() *OverridesPopPoolsObservation {
	if in == nil {
		return nil
	}
	out := new(OverridesPopPoolsObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OverridesPopPoolsParameters) DeepCopyInto(out *OverridesPopPoolsParameters) {
	*out = *in
	if in.PoolIds != nil {
		in, out := &in.PoolIds, &out.PoolIds
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
	if in.Pop != nil {
		in, out := &in.Pop, &out.Pop
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OverridesPopPoolsParameters.
func (in *OverridesPopPoolsParameters) DeepCopy() *OverridesPopPoolsParameters {
	if in == nil {
		return nil
	}
	out := new(OverridesPopPoolsParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OverridesRegionPoolsObservation) DeepCopyInto(out *OverridesRegionPoolsObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OverridesRegionPoolsObservation.
func (in *OverridesRegionPoolsObservation) DeepCopy() *OverridesRegionPoolsObservation {
	if in == nil {
		return nil
	}
	out := new(OverridesRegionPoolsObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OverridesRegionPoolsParameters) DeepCopyInto(out *OverridesRegionPoolsParameters) {
	*out = *in
	if in.PoolIds != nil {
		in, out := &in.PoolIds, &out.PoolIds
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
	if in.Region != nil {
		in, out := &in.Region, &out.Region
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OverridesRegionPoolsParameters.
func (in *OverridesRegionPoolsParameters) DeepCopy() *OverridesRegionPoolsParameters {
	if in == nil {
		return nil
	}
	out := new(OverridesRegionPoolsParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PopPoolsObservation) DeepCopyInto(out *PopPoolsObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PopPoolsObservation.
func (in *PopPoolsObservation) DeepCopy() *PopPoolsObservation {
	if in == nil {
		return nil
	}
	out := new(PopPoolsObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PopPoolsParameters) DeepCopyInto(out *PopPoolsParameters) {
	*out = *in
	if in.PoolIds != nil {
		in, out := &in.PoolIds, &out.PoolIds
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
	if in.Pop != nil {
		in, out := &in.Pop, &out.Pop
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PopPoolsParameters.
func (in *PopPoolsParameters) DeepCopy() *PopPoolsParameters {
	if in == nil {
		return nil
	}
	out := new(PopPoolsParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RegionPoolsObservation) DeepCopyInto(out *RegionPoolsObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RegionPoolsObservation.
func (in *RegionPoolsObservation) DeepCopy() *RegionPoolsObservation {
	if in == nil {
		return nil
	}
	out := new(RegionPoolsObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RegionPoolsParameters) DeepCopyInto(out *RegionPoolsParameters) {
	*out = *in
	if in.PoolIds != nil {
		in, out := &in.PoolIds, &out.PoolIds
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
	if in.Region != nil {
		in, out := &in.Region, &out.Region
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RegionPoolsParameters.
func (in *RegionPoolsParameters) DeepCopy() *RegionPoolsParameters {
	if in == nil {
		return nil
	}
	out := new(RegionPoolsParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RulesObservation) DeepCopyInto(out *RulesObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RulesObservation.
func (in *RulesObservation) DeepCopy() *RulesObservation {
	if in == nil {
		return nil
	}
	out := new(RulesObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RulesParameters) DeepCopyInto(out *RulesParameters) {
	*out = *in
	if in.Condition != nil {
		in, out := &in.Condition, &out.Condition
		*out = new(string)
		**out = **in
	}
	if in.Disabled != nil {
		in, out := &in.Disabled, &out.Disabled
		*out = new(bool)
		**out = **in
	}
	if in.FixedResponse != nil {
		in, out := &in.FixedResponse, &out.FixedResponse
		*out = make([]FixedResponseParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
	if in.Overrides != nil {
		in, out := &in.Overrides, &out.Overrides
		*out = make([]OverridesParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Priority != nil {
		in, out := &in.Priority, &out.Priority
		*out = new(float64)
		**out = **in
	}
	if in.Terminates != nil {
		in, out := &in.Terminates, &out.Terminates
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RulesParameters.
func (in *RulesParameters) DeepCopy() *RulesParameters {
	if in == nil {
		return nil
	}
	out := new(RulesParameters)
	in.DeepCopyInto(out)
	return out
}
