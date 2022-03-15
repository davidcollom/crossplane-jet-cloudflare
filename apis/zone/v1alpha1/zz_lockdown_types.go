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
<<<<<<< HEAD

)




type ConfigurationsObservation struct {

}


type ConfigurationsParameters struct {


// +kubebuilder:validation:Required
Target *string `json:"target" tf:"target,omitempty"`

// +kubebuilder:validation:Required
Value *string `json:"value" tf:"value,omitempty"`
}


type LockdownObservation struct {


ID *string `json:"id,omitempty" tf:"id,omitempty"`
}


type LockdownParameters struct {


// +kubebuilder:validation:Required
Configurations []ConfigurationsParameters `json:"configurations" tf:"configurations,omitempty"`

// +kubebuilder:validation:Optional
Description *string `json:"description,omitempty" tf:"description,omitempty"`

// +kubebuilder:validation:Optional
Paused *bool `json:"paused,omitempty" tf:"paused,omitempty"`

// +kubebuilder:validation:Optional
Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

// +kubebuilder:validation:Required
Urls []*string `json:"urls" tf:"urls,omitempty"`

// +kubebuilder:validation:Required
ZoneID *string `json:"zoneId" tf:"zone_id,omitempty"`
=======
)

type ConfigurationsObservation struct {
}

type ConfigurationsParameters struct {

	// +kubebuilder:validation:Required
	Target *string `json:"target" tf:"target,omitempty"`

	// +kubebuilder:validation:Required
	Value *string `json:"value" tf:"value,omitempty"`
}

type LockdownObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type LockdownParameters struct {

	// +kubebuilder:validation:Required
	Configurations []ConfigurationsParameters `json:"configurations" tf:"configurations,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Paused *bool `json:"paused,omitempty" tf:"paused,omitempty"`

	// +kubebuilder:validation:Optional
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// +kubebuilder:validation:Required
	Urls []*string `json:"urls" tf:"urls,omitempty"`

	// +kubebuilder:validation:Required
	ZoneID *string `json:"zoneId" tf:"zone_id,omitempty"`
>>>>>>> 205d351
}

// LockdownSpec defines the desired state of Lockdown
type LockdownSpec struct {
	v1.ResourceSpec `json:",inline"`
<<<<<<< HEAD
	ForProvider       LockdownParameters `json:"forProvider"`
=======
	ForProvider     LockdownParameters `json:"forProvider"`
>>>>>>> 205d351
}

// LockdownStatus defines the observed state of Lockdown.
type LockdownStatus struct {
	v1.ResourceStatus `json:",inline"`
<<<<<<< HEAD
	AtProvider          LockdownObservation `json:"atProvider,omitempty"`
=======
	AtProvider        LockdownObservation `json:"atProvider,omitempty"`
>>>>>>> 205d351
}

// +kubebuilder:object:root=true

// Lockdown is the Schema for the Lockdowns API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type Lockdown struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              LockdownSpec   `json:"spec"`
	Status            LockdownStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// LockdownList contains a list of Lockdowns
type LockdownList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Lockdown `json:"items"`
}

// Repository type metadata.
var (
	Lockdown_Kind             = "Lockdown"
	Lockdown_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Lockdown_Kind}.String()
	Lockdown_KindAPIVersion   = Lockdown_Kind + "." + CRDGroupVersion.String()
	Lockdown_GroupVersionKind = CRDGroupVersion.WithKind(Lockdown_Kind)
)

func init() {
	SchemeBuilder.Register(&Lockdown{}, &LockdownList{})
}