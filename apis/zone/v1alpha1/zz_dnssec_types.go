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




type DNSSECObservation struct {


Algorithm *string `json:"algorithm,omitempty" tf:"algorithm,omitempty"`

Digest *string `json:"digest,omitempty" tf:"digest,omitempty"`

DigestAlgorithm *string `json:"digestAlgorithm,omitempty" tf:"digest_algorithm,omitempty"`

DigestType *string `json:"digestType,omitempty" tf:"digest_type,omitempty"`

Ds *string `json:"ds,omitempty" tf:"ds,omitempty"`

Flags *float64 `json:"flags,omitempty" tf:"flags,omitempty"`

ID *string `json:"id,omitempty" tf:"id,omitempty"`

KeyTag *float64 `json:"keyTag,omitempty" tf:"key_tag,omitempty"`

KeyType *string `json:"keyType,omitempty" tf:"key_type,omitempty"`

PublicKey *string `json:"publicKey,omitempty" tf:"public_key,omitempty"`

Status *string `json:"status,omitempty" tf:"status,omitempty"`
}


type DNSSECParameters struct {


// +kubebuilder:validation:Optional
ModifiedOn *string `json:"modifiedOn,omitempty" tf:"modified_on,omitempty"`

// +kubebuilder:validation:Required
ZoneID *string `json:"zoneId" tf:"zone_id,omitempty"`
=======
)

type DNSSECObservation struct {
	Algorithm *string `json:"algorithm,omitempty" tf:"algorithm,omitempty"`

	Digest *string `json:"digest,omitempty" tf:"digest,omitempty"`

	DigestAlgorithm *string `json:"digestAlgorithm,omitempty" tf:"digest_algorithm,omitempty"`

	DigestType *string `json:"digestType,omitempty" tf:"digest_type,omitempty"`

	Ds *string `json:"ds,omitempty" tf:"ds,omitempty"`

	Flags *float64 `json:"flags,omitempty" tf:"flags,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	KeyTag *float64 `json:"keyTag,omitempty" tf:"key_tag,omitempty"`

	KeyType *string `json:"keyType,omitempty" tf:"key_type,omitempty"`

	PublicKey *string `json:"publicKey,omitempty" tf:"public_key,omitempty"`

	Status *string `json:"status,omitempty" tf:"status,omitempty"`
}

type DNSSECParameters struct {

	// +kubebuilder:validation:Optional
	ModifiedOn *string `json:"modifiedOn,omitempty" tf:"modified_on,omitempty"`

	// +kubebuilder:validation:Required
	ZoneID *string `json:"zoneId" tf:"zone_id,omitempty"`
>>>>>>> 205d351
}

// DNSSECSpec defines the desired state of DNSSEC
type DNSSECSpec struct {
	v1.ResourceSpec `json:",inline"`
<<<<<<< HEAD
	ForProvider       DNSSECParameters `json:"forProvider"`
=======
	ForProvider     DNSSECParameters `json:"forProvider"`
>>>>>>> 205d351
}

// DNSSECStatus defines the observed state of DNSSEC.
type DNSSECStatus struct {
	v1.ResourceStatus `json:",inline"`
<<<<<<< HEAD
	AtProvider          DNSSECObservation `json:"atProvider,omitempty"`
=======
	AtProvider        DNSSECObservation `json:"atProvider,omitempty"`
>>>>>>> 205d351
}

// +kubebuilder:object:root=true

// DNSSEC is the Schema for the DNSSECs API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type DNSSEC struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DNSSECSpec   `json:"spec"`
	Status            DNSSECStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DNSSECList contains a list of DNSSECs
type DNSSECList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DNSSEC `json:"items"`
}

// Repository type metadata.
var (
	DNSSEC_Kind             = "DNSSEC"
	DNSSEC_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: DNSSEC_Kind}.String()
	DNSSEC_KindAPIVersion   = DNSSEC_Kind + "." + CRDGroupVersion.String()
	DNSSEC_GroupVersionKind = CRDGroupVersion.WithKind(DNSSEC_Kind)
)

func init() {
	SchemeBuilder.Register(&DNSSEC{}, &DNSSECList{})
}
