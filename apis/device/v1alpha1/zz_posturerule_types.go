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

type InputObservation struct {
}

type InputParameters struct {

	// The workspace one device compliance status.
	// +kubebuilder:validation:Optional
	ComplianceStatus *string `json:"complianceStatus,omitempty" tf:"compliance_status,omitempty"`

	// The workspace one connection id.
	// +kubebuilder:validation:Optional
	ConnectionID *string `json:"connectionId,omitempty" tf:"connection_id,omitempty"`

	// The domain that the client must join.
	// +kubebuilder:validation:Optional
	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	// True if the firewall must be enabled.
	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// Checks if the file should exist.
	// +kubebuilder:validation:Optional
	Exists *bool `json:"exists,omitempty" tf:"exists,omitempty"`

	// The Teams List id.
	// +kubebuilder:validation:Optional
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// The version comparison operator.
	// +kubebuilder:validation:Optional
	Operator *string `json:"operator,omitempty" tf:"operator,omitempty"`

	// The path to the file.
	// +kubebuilder:validation:Optional
	Path *string `json:"path,omitempty" tf:"path,omitempty"`

	// True if all drives must be encrypted.
	// +kubebuilder:validation:Optional
	RequireAll *bool `json:"requireAll,omitempty" tf:"require_all,omitempty"`

	// Checks if the application should be running
	// +kubebuilder:validation:Optional
	Running *bool `json:"running,omitempty" tf:"running,omitempty"`

	// The sha256 hash of the file.
	// +kubebuilder:validation:Optional
	Sha256 *string `json:"sha256,omitempty" tf:"sha256,omitempty"`

	// The thumbprint of the file certificate.
	// +kubebuilder:validation:Optional
	Thumbprint *string `json:"thumbprint,omitempty" tf:"thumbprint,omitempty"`

	// The operating system semantic version.
	// +kubebuilder:validation:Optional
	Version *string `json:"version,omitempty" tf:"version,omitempty"`
}

type MatchObservation struct {
}

type MatchParameters struct {

	// +kubebuilder:validation:Optional
	Platform *string `json:"platform,omitempty" tf:"platform,omitempty"`
}

type PostureRuleObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type PostureRuleParameters struct {

	// +kubebuilder:validation:Required
	AccountID *string `json:"accountId" tf:"account_id,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Input []InputParameters `json:"input,omitempty" tf:"input,omitempty"`

	// +kubebuilder:validation:Optional
	Match []MatchParameters `json:"match,omitempty" tf:"match,omitempty"`

	// +kubebuilder:validation:Optional
	Schedule *string `json:"schedule,omitempty" tf:"schedule,omitempty"`

	// +kubebuilder:validation:Required
	Type *string `json:"type" tf:"type,omitempty"`
}

// PostureRuleSpec defines the desired state of PostureRule
type PostureRuleSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     PostureRuleParameters `json:"forProvider"`
}

// PostureRuleStatus defines the observed state of PostureRule.
type PostureRuleStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        PostureRuleObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// PostureRule is the Schema for the PostureRules API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type PostureRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PostureRuleSpec   `json:"spec"`
	Status            PostureRuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PostureRuleList contains a list of PostureRules
type PostureRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PostureRule `json:"items"`
}

// Repository type metadata.
var (
	PostureRule_Kind             = "PostureRule"
	PostureRule_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: PostureRule_Kind}.String()
	PostureRule_KindAPIVersion   = PostureRule_Kind + "." + CRDGroupVersion.String()
	PostureRule_GroupVersionKind = CRDGroupVersion.WithKind(PostureRule_Kind)
)

func init() {
	SchemeBuilder.Register(&PostureRule{}, &PostureRuleList{})
}
