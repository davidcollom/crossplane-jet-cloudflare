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

type OverrideObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	OverrideID *string `json:"overrideId,omitempty" tf:"override_id,omitempty"`
}

type OverrideParameters struct {

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Groups map[string]*string `json:"groups,omitempty" tf:"groups,omitempty"`

	// +kubebuilder:validation:Optional
	Paused *bool `json:"paused,omitempty" tf:"paused,omitempty"`

	// +kubebuilder:validation:Optional
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// +kubebuilder:validation:Optional
	RewriteAction map[string]*string `json:"rewriteAction,omitempty" tf:"rewrite_action,omitempty"`

	// +kubebuilder:validation:Optional
	Rules map[string]*string `json:"rules,omitempty" tf:"rules,omitempty"`

	// +kubebuilder:validation:Required
	Urls []*string `json:"urls" tf:"urls,omitempty"`

	// +kubebuilder:validation:Required
	ZoneID *string `json:"zoneId" tf:"zone_id,omitempty"`
}

// OverrideSpec defines the desired state of Override
type OverrideSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     OverrideParameters `json:"forProvider"`
}

// OverrideStatus defines the observed state of Override.
type OverrideStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        OverrideObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Override is the Schema for the Overrides API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type Override struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OverrideSpec   `json:"spec"`
	Status            OverrideStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OverrideList contains a list of Overrides
type OverrideList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Override `json:"items"`
}

// Repository type metadata.
var (
	Override_Kind             = "Override"
	Override_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Override_Kind}.String()
	Override_KindAPIVersion   = Override_Kind + "." + CRDGroupVersion.String()
	Override_GroupVersionKind = CRDGroupVersion.WithKind(Override_Kind)
)

func init() {
	SchemeBuilder.Register(&Override{}, &OverrideList{})
}
