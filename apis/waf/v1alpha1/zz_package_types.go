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

type PackageObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type PackageParameters struct {

	// +kubebuilder:validation:Optional
	ActionMode *string `json:"actionMode,omitempty" tf:"action_mode,omitempty"`

	// +kubebuilder:validation:Required
	PackageID *string `json:"packageId" tf:"package_id,omitempty"`

	// +kubebuilder:validation:Optional
	Sensitivity *string `json:"sensitivity,omitempty" tf:"sensitivity,omitempty"`

	// +kubebuilder:validation:Required
	ZoneID *string `json:"zoneId" tf:"zone_id,omitempty"`
}

// PackageSpec defines the desired state of Package
type PackageSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     PackageParameters `json:"forProvider"`
}

// PackageStatus defines the observed state of Package.
type PackageStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        PackageObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Package is the Schema for the Packages API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type Package struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PackageSpec   `json:"spec"`
	Status            PackageStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PackageList contains a list of Packages
type PackageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Package `json:"items"`
}

// Repository type metadata.
var (
	Package_Kind             = "Package"
	Package_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Package_Kind}.String()
	Package_KindAPIVersion   = Package_Kind + "." + CRDGroupVersion.String()
	Package_GroupVersionKind = CRDGroupVersion.WithKind(Package_Kind)
)

func init() {
	SchemeBuilder.Register(&Package{}, &PackageList{})
}
