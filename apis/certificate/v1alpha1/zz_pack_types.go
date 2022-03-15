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




type PackObservation struct {


ID *string `json:"id,omitempty" tf:"id,omitempty"`
}


type PackParameters struct {


// +kubebuilder:validation:Optional
CertificateAuthority *string `json:"certificateAuthority,omitempty" tf:"certificate_authority,omitempty"`

// +kubebuilder:validation:Optional
CloudflareBranding *bool `json:"cloudflareBranding,omitempty" tf:"cloudflare_branding,omitempty"`

// +kubebuilder:validation:Required
Hosts []*string `json:"hosts" tf:"hosts,omitempty"`

// +kubebuilder:validation:Required
Type *string `json:"type" tf:"type,omitempty"`

// +kubebuilder:validation:Optional
ValidationErrors []ValidationErrorsParameters `json:"validationErrors,omitempty" tf:"validation_errors,omitempty"`

// +kubebuilder:validation:Optional
ValidationMethod *string `json:"validationMethod,omitempty" tf:"validation_method,omitempty"`

// +kubebuilder:validation:Optional
ValidationRecords []ValidationRecordsParameters `json:"validationRecords,omitempty" tf:"validation_records,omitempty"`

// +kubebuilder:validation:Optional
ValidityDays *float64 `json:"validityDays,omitempty" tf:"validity_days,omitempty"`

// +kubebuilder:validation:Required
ZoneID *string `json:"zoneId" tf:"zone_id,omitempty"`
}


type ValidationErrorsObservation struct {


Message *string `json:"message,omitempty" tf:"message,omitempty"`
}


type ValidationErrorsParameters struct {

}


type ValidationRecordsObservation struct {

}


type ValidationRecordsParameters struct {


// +kubebuilder:validation:Optional
CnameName *string `json:"cnameName,omitempty" tf:"cname_name,omitempty"`

// +kubebuilder:validation:Optional
CnameTarget *string `json:"cnameTarget,omitempty" tf:"cname_target,omitempty"`

// +kubebuilder:validation:Optional
Emails []*string `json:"emails,omitempty" tf:"emails,omitempty"`

// +kubebuilder:validation:Optional
HTTPBody *string `json:"httpBody,omitempty" tf:"http_body,omitempty"`

// +kubebuilder:validation:Optional
HTTPURL *string `json:"httpUrl,omitempty" tf:"http_url,omitempty"`

// +kubebuilder:validation:Optional
TxtName *string `json:"txtName,omitempty" tf:"txt_name,omitempty"`

// +kubebuilder:validation:Optional
TxtValue *string `json:"txtValue,omitempty" tf:"txt_value,omitempty"`
=======
)

type PackObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type PackParameters struct {

	// +kubebuilder:validation:Optional
	CertificateAuthority *string `json:"certificateAuthority,omitempty" tf:"certificate_authority,omitempty"`

	// +kubebuilder:validation:Optional
	CloudflareBranding *bool `json:"cloudflareBranding,omitempty" tf:"cloudflare_branding,omitempty"`

	// +kubebuilder:validation:Required
	Hosts []*string `json:"hosts" tf:"hosts,omitempty"`

	// +kubebuilder:validation:Required
	Type *string `json:"type" tf:"type,omitempty"`

	// +kubebuilder:validation:Optional
	ValidationErrors []ValidationErrorsParameters `json:"validationErrors,omitempty" tf:"validation_errors,omitempty"`

	// +kubebuilder:validation:Optional
	ValidationMethod *string `json:"validationMethod,omitempty" tf:"validation_method,omitempty"`

	// +kubebuilder:validation:Optional
	ValidationRecords []ValidationRecordsParameters `json:"validationRecords,omitempty" tf:"validation_records,omitempty"`

	// +kubebuilder:validation:Optional
	ValidityDays *float64 `json:"validityDays,omitempty" tf:"validity_days,omitempty"`

	// +kubebuilder:validation:Required
	ZoneID *string `json:"zoneId" tf:"zone_id,omitempty"`
}

type ValidationErrorsObservation struct {
	Message *string `json:"message,omitempty" tf:"message,omitempty"`
}

type ValidationErrorsParameters struct {
}

type ValidationRecordsObservation struct {
}

type ValidationRecordsParameters struct {

	// +kubebuilder:validation:Optional
	CnameName *string `json:"cnameName,omitempty" tf:"cname_name,omitempty"`

	// +kubebuilder:validation:Optional
	CnameTarget *string `json:"cnameTarget,omitempty" tf:"cname_target,omitempty"`

	// +kubebuilder:validation:Optional
	Emails []*string `json:"emails,omitempty" tf:"emails,omitempty"`

	// +kubebuilder:validation:Optional
	HTTPBody *string `json:"httpBody,omitempty" tf:"http_body,omitempty"`

	// +kubebuilder:validation:Optional
	HTTPURL *string `json:"httpUrl,omitempty" tf:"http_url,omitempty"`

	// +kubebuilder:validation:Optional
	TxtName *string `json:"txtName,omitempty" tf:"txt_name,omitempty"`

	// +kubebuilder:validation:Optional
	TxtValue *string `json:"txtValue,omitempty" tf:"txt_value,omitempty"`
>>>>>>> 205d351
}

// PackSpec defines the desired state of Pack
type PackSpec struct {
	v1.ResourceSpec `json:",inline"`
<<<<<<< HEAD
	ForProvider       PackParameters `json:"forProvider"`
=======
	ForProvider     PackParameters `json:"forProvider"`
>>>>>>> 205d351
}

// PackStatus defines the observed state of Pack.
type PackStatus struct {
	v1.ResourceStatus `json:",inline"`
<<<<<<< HEAD
	AtProvider          PackObservation `json:"atProvider,omitempty"`
=======
	AtProvider        PackObservation `json:"atProvider,omitempty"`
>>>>>>> 205d351
}

// +kubebuilder:object:root=true

// Pack is the Schema for the Packs API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type Pack struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PackSpec   `json:"spec"`
	Status            PackStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PackList contains a list of Packs
type PackList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Pack `json:"items"`
}

// Repository type metadata.
var (
	Pack_Kind             = "Pack"
	Pack_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Pack_Kind}.String()
	Pack_KindAPIVersion   = Pack_Kind + "." + CRDGroupVersion.String()
	Pack_GroupVersionKind = CRDGroupVersion.WithKind(Pack_Kind)
)

func init() {
	SchemeBuilder.Register(&Pack{}, &PackList{})
}
