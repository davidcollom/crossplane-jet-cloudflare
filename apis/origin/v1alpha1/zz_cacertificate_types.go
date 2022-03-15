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

type CACertificateObservation struct {
	Certificate *string `json:"certificate,omitempty" tf:"certificate,omitempty"`

	ExpiresOn *string `json:"expiresOn,omitempty" tf:"expires_on,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type CACertificateParameters struct {

	// +kubebuilder:validation:Optional
	Csr *string `json:"csr,omitempty" tf:"csr,omitempty"`

	// +kubebuilder:validation:Required
	Hostnames []*string `json:"hostnames" tf:"hostnames,omitempty"`

	// +kubebuilder:validation:Required
	RequestType *string `json:"requestType" tf:"request_type,omitempty"`

	// +kubebuilder:validation:Optional
	RequestedValidity *float64 `json:"requestedValidity,omitempty" tf:"requested_validity,omitempty"`
}

// CACertificateSpec defines the desired state of CACertificate
type CACertificateSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     CACertificateParameters `json:"forProvider"`
}

// CACertificateStatus defines the observed state of CACertificate.
type CACertificateStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        CACertificateObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// CACertificate is the Schema for the CACertificates API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type CACertificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CACertificateSpec   `json:"spec"`
	Status            CACertificateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CACertificateList contains a list of CACertificates
type CACertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CACertificate `json:"items"`
}

// Repository type metadata.
var (
	CACertificate_Kind             = "CACertificate"
	CACertificate_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: CACertificate_Kind}.String()
	CACertificate_KindAPIVersion   = CACertificate_Kind + "." + CRDGroupVersion.String()
	CACertificate_GroupVersionKind = CRDGroupVersion.WithKind(CACertificate_Kind)
)

func init() {
	SchemeBuilder.Register(&CACertificate{}, &CACertificateList{})
}
