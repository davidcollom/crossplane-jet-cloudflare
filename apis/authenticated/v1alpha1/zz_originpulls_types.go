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

type OriginPullsObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type OriginPullsParameters struct {

	// +kubebuilder:validation:Optional
	AuthenticatedOriginPullsCertificate *string `json:"authenticatedOriginPullsCertificate,omitempty" tf:"authenticated_origin_pulls_certificate,omitempty"`

	// +kubebuilder:validation:Required
	Enabled *bool `json:"enabled" tf:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`

	// +kubebuilder:validation:Required
	ZoneID *string `json:"zoneId" tf:"zone_id,omitempty"`
}

// OriginPullsSpec defines the desired state of OriginPulls
type OriginPullsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     OriginPullsParameters `json:"forProvider"`
}

// OriginPullsStatus defines the observed state of OriginPulls.
type OriginPullsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        OriginPullsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// OriginPulls is the Schema for the OriginPullss API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type OriginPulls struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OriginPullsSpec   `json:"spec"`
	Status            OriginPullsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OriginPullsList contains a list of OriginPullss
type OriginPullsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OriginPulls `json:"items"`
}

// Repository type metadata.
var (
	OriginPulls_Kind             = "OriginPulls"
	OriginPulls_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: OriginPulls_Kind}.String()
	OriginPulls_KindAPIVersion   = OriginPulls_Kind + "." + CRDGroupVersion.String()
	OriginPulls_GroupVersionKind = CRDGroupVersion.WithKind(OriginPulls_Kind)
)

func init() {
	SchemeBuilder.Register(&OriginPulls{}, &OriginPullsList{})
}
