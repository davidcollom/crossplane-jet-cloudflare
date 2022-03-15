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

// Code generated by terrajet. DO NOT EDIT.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

type BalancerPoolObservation struct {
	CreatedOn *string `json:"createdOn,omitempty" tf:"created_on,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	ModifiedOn *string `json:"modifiedOn,omitempty" tf:"modified_on,omitempty"`
}

type BalancerPoolParameters struct {

	// +kubebuilder:validation:Optional
	CheckRegions []*string `json:"checkRegions,omitempty" tf:"check_regions,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	Latitude *float64 `json:"latitude,omitempty" tf:"latitude,omitempty"`

	// +kubebuilder:validation:Optional
	LoadShedding []LoadSheddingParameters `json:"loadShedding,omitempty" tf:"load_shedding,omitempty"`

	// +kubebuilder:validation:Optional
	Longitude *float64 `json:"longitude,omitempty" tf:"longitude,omitempty"`

	// +kubebuilder:validation:Optional
	MinimumOrigins *float64 `json:"minimumOrigins,omitempty" tf:"minimum_origins,omitempty"`

	// +kubebuilder:validation:Optional
	Monitor *string `json:"monitor,omitempty" tf:"monitor,omitempty"`

	// +kubebuilder:validation:Optional
	NotificationEmail *string `json:"notificationEmail,omitempty" tf:"notification_email,omitempty"`

	// +kubebuilder:validation:Optional
	OriginSteering []OriginSteeringParameters `json:"originSteering,omitempty" tf:"origin_steering,omitempty"`

	// +kubebuilder:validation:Required
	Origins []OriginsParameters `json:"origins" tf:"origins,omitempty"`
}

type LoadSheddingObservation struct {
}

type LoadSheddingParameters struct {

	// +kubebuilder:validation:Optional
	DefaultPercent *float64 `json:"defaultPercent,omitempty" tf:"default_percent,omitempty"`

	// +kubebuilder:validation:Optional
	DefaultPolicy *string `json:"defaultPolicy,omitempty" tf:"default_policy,omitempty"`

	// +kubebuilder:validation:Optional
	SessionPercent *float64 `json:"sessionPercent,omitempty" tf:"session_percent,omitempty"`

	// +kubebuilder:validation:Optional
	SessionPolicy *string `json:"sessionPolicy,omitempty" tf:"session_policy,omitempty"`
}

type OriginSteeringObservation struct {
}

type OriginSteeringParameters struct {

	// +kubebuilder:validation:Optional
	Policy *string `json:"policy,omitempty" tf:"policy,omitempty"`
}

type OriginsHeaderObservation struct {
}

type OriginsHeaderParameters struct {

	// +kubebuilder:validation:Required
	Header *string `json:"header" tf:"header,omitempty"`

	// +kubebuilder:validation:Required
	Values []*string `json:"values" tf:"values,omitempty"`
}

type OriginsObservation struct {
}

type OriginsParameters struct {

	// +kubebuilder:validation:Required
	Address *string `json:"address" tf:"address,omitempty"`

	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	Header []OriginsHeaderParameters `json:"header,omitempty" tf:"header,omitempty"`

	// +kubebuilder:validation:Required
	Name *string `json:"name" tf:"name,omitempty"`

	// +kubebuilder:validation:Optional
	Weight *float64 `json:"weight,omitempty" tf:"weight,omitempty"`
}

// BalancerPoolSpec defines the desired state of BalancerPool
type BalancerPoolSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     BalancerPoolParameters `json:"forProvider"`
}

// BalancerPoolStatus defines the observed state of BalancerPool.
type BalancerPoolStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        BalancerPoolObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// BalancerPool is the Schema for the BalancerPools API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type BalancerPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BalancerPoolSpec   `json:"spec"`
	Status            BalancerPoolStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BalancerPoolList contains a list of BalancerPools
type BalancerPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BalancerPool `json:"items"`
}

// Repository type metadata.
var (
	BalancerPool_Kind             = "BalancerPool"
	BalancerPool_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: BalancerPool_Kind}.String()
	BalancerPool_KindAPIVersion   = BalancerPool_Kind + "." + CRDGroupVersion.String()
	BalancerPool_GroupVersionKind = CRDGroupVersion.WithKind(BalancerPool_Kind)
)

func init() {
	SchemeBuilder.Register(&BalancerPool{}, &BalancerPoolList{})
}