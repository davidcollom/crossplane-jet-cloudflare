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




type ConditionObservation struct {

}


type ConditionParameters struct {


// +kubebuilder:validation:Optional
RequestIP []RequestIPParameters `json:"requestIp,omitempty" tf:"request_ip,omitempty"`
}


type PolicyObservation struct {

}


type PolicyParameters struct {


// +kubebuilder:validation:Optional
Effect *string `json:"effect,omitempty" tf:"effect,omitempty"`

// +kubebuilder:validation:Required
PermissionGroups []*string `json:"permissionGroups" tf:"permission_groups,omitempty"`

// +kubebuilder:validation:Required
Resources map[string]*string `json:"resources" tf:"resources,omitempty"`
}


type RequestIPObservation struct {

}


type RequestIPParameters struct {


// +kubebuilder:validation:Optional
In []*string `json:"in,omitempty" tf:"in,omitempty"`

// +kubebuilder:validation:Optional
NotIn []*string `json:"notIn,omitempty" tf:"not_in,omitempty"`
}


type TokenObservation struct {


ID *string `json:"id,omitempty" tf:"id,omitempty"`

IssuedOn *string `json:"issuedOn,omitempty" tf:"issued_on,omitempty"`

ModifiedOn *string `json:"modifiedOn,omitempty" tf:"modified_on,omitempty"`

Status *string `json:"status,omitempty" tf:"status,omitempty"`
}


type TokenParameters struct {


// +kubebuilder:validation:Optional
Condition []ConditionParameters `json:"condition,omitempty" tf:"condition,omitempty"`

// +kubebuilder:validation:Required
Policy []PolicyParameters `json:"policy" tf:"policy,omitempty"`
=======
)

type ConditionObservation struct {
}

type ConditionParameters struct {

	// +kubebuilder:validation:Optional
	RequestIP []RequestIPParameters `json:"requestIp,omitempty" tf:"request_ip,omitempty"`
}

type PolicyObservation struct {
}

type PolicyParameters struct {

	// +kubebuilder:validation:Optional
	Effect *string `json:"effect,omitempty" tf:"effect,omitempty"`

	// +kubebuilder:validation:Required
	PermissionGroups []*string `json:"permissionGroups" tf:"permission_groups,omitempty"`

	// +kubebuilder:validation:Required
	Resources map[string]*string `json:"resources" tf:"resources,omitempty"`
}

type RequestIPObservation struct {
}

type RequestIPParameters struct {

	// +kubebuilder:validation:Optional
	In []*string `json:"in,omitempty" tf:"in,omitempty"`

	// +kubebuilder:validation:Optional
	NotIn []*string `json:"notIn,omitempty" tf:"not_in,omitempty"`
}

type TokenObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	IssuedOn *string `json:"issuedOn,omitempty" tf:"issued_on,omitempty"`

	ModifiedOn *string `json:"modifiedOn,omitempty" tf:"modified_on,omitempty"`

	Status *string `json:"status,omitempty" tf:"status,omitempty"`
}

type TokenParameters struct {

	// +kubebuilder:validation:Optional
	Condition []ConditionParameters `json:"condition,omitempty" tf:"condition,omitempty"`

	// +kubebuilder:validation:Required
	Policy []PolicyParameters `json:"policy" tf:"policy,omitempty"`
>>>>>>> 205d351
}

// TokenSpec defines the desired state of Token
type TokenSpec struct {
	v1.ResourceSpec `json:",inline"`
<<<<<<< HEAD
	ForProvider       TokenParameters `json:"forProvider"`
=======
	ForProvider     TokenParameters `json:"forProvider"`
>>>>>>> 205d351
}

// TokenStatus defines the observed state of Token.
type TokenStatus struct {
	v1.ResourceStatus `json:",inline"`
<<<<<<< HEAD
	AtProvider          TokenObservation `json:"atProvider,omitempty"`
=======
	AtProvider        TokenObservation `json:"atProvider,omitempty"`
>>>>>>> 205d351
}

// +kubebuilder:object:root=true

// Token is the Schema for the Tokens API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type Token struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TokenSpec   `json:"spec"`
	Status            TokenStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TokenList contains a list of Tokens
type TokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Token `json:"items"`
}

// Repository type metadata.
var (
	Token_Kind             = "Token"
	Token_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Token_Kind}.String()
	Token_KindAPIVersion   = Token_Kind + "." + CRDGroupVersion.String()
	Token_GroupVersionKind = CRDGroupVersion.WithKind(Token_Kind)
)

func init() {
	SchemeBuilder.Register(&Token{}, &TokenList{})
}
