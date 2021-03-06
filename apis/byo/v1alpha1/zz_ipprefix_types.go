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

type IPPrefixObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type IPPrefixParameters struct {

	// +kubebuilder:validation:Optional
	Advertisement *string `json:"advertisement,omitempty" tf:"advertisement,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Required
	PrefixID *string `json:"prefixId" tf:"prefix_id,omitempty"`
}

// IPPrefixSpec defines the desired state of IPPrefix
type IPPrefixSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     IPPrefixParameters `json:"forProvider"`
}

// IPPrefixStatus defines the observed state of IPPrefix.
type IPPrefixStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        IPPrefixObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// IPPrefix is the Schema for the IPPrefixs API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type IPPrefix struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IPPrefixSpec   `json:"spec"`
	Status            IPPrefixStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IPPrefixList contains a list of IPPrefixs
type IPPrefixList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IPPrefix `json:"items"`
}

// Repository type metadata.
var (
	IPPrefix_Kind             = "IPPrefix"
	IPPrefix_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: IPPrefix_Kind}.String()
	IPPrefix_KindAPIVersion   = IPPrefix_Kind + "." + CRDGroupVersion.String()
	IPPrefix_GroupVersionKind = CRDGroupVersion.WithKind(IPPrefix_Kind)
)

func init() {
	SchemeBuilder.Register(&IPPrefix{}, &IPPrefixList{})
}
