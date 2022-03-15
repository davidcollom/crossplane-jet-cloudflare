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

type BisoAdminControlsObservation struct {
}

type BisoAdminControlsParameters struct {

	// +kubebuilder:validation:Optional
	DisableCopyPaste *bool `json:"disableCopyPaste,omitempty" tf:"disable_copy_paste,omitempty"`

	// +kubebuilder:validation:Optional
	DisableDownload *bool `json:"disableDownload,omitempty" tf:"disable_download,omitempty"`

	// +kubebuilder:validation:Optional
	DisableKeyboard *bool `json:"disableKeyboard,omitempty" tf:"disable_keyboard,omitempty"`

	// +kubebuilder:validation:Optional
	DisablePrinting *bool `json:"disablePrinting,omitempty" tf:"disable_printing,omitempty"`

	// +kubebuilder:validation:Optional
	DisableUpload *bool `json:"disableUpload,omitempty" tf:"disable_upload,omitempty"`
}

type CheckSessionObservation struct {
}

type CheckSessionParameters struct {

	// +kubebuilder:validation:Required
	Duration *string `json:"duration" tf:"duration,omitempty"`

	// +kubebuilder:validation:Required
	Enforce *bool `json:"enforce" tf:"enforce,omitempty"`
}

type L4OverrideObservation struct {
}

type L4OverrideParameters struct {

	// +kubebuilder:validation:Required
	IP *string `json:"ip" tf:"ip,omitempty"`

	// +kubebuilder:validation:Required
	Port *float64 `json:"port" tf:"port,omitempty"`
}

type RuleObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	Version *float64 `json:"version,omitempty" tf:"version,omitempty"`
}

type RuleParameters struct {

	// +kubebuilder:validation:Required
	AccountID *string `json:"accountId" tf:"account_id,omitempty"`

	// +kubebuilder:validation:Required
	Action *string `json:"action" tf:"action,omitempty"`

	// +kubebuilder:validation:Required
	Description *string `json:"description" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	DevicePosture *string `json:"devicePosture,omitempty" tf:"device_posture,omitempty"`

	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	Filters []*string `json:"filters,omitempty" tf:"filters,omitempty"`

	// +kubebuilder:validation:Optional
	Identity *string `json:"identity,omitempty" tf:"identity,omitempty"`

	// +kubebuilder:validation:Required
	Precedence *float64 `json:"precedence" tf:"precedence,omitempty"`

	// +kubebuilder:validation:Optional
	RuleSettings []RuleSettingsParameters `json:"ruleSettings,omitempty" tf:"rule_settings,omitempty"`

	// +kubebuilder:validation:Optional
	Traffic *string `json:"traffic,omitempty" tf:"traffic,omitempty"`
}

type RuleSettingsObservation struct {
}

type RuleSettingsParameters struct {

	// +kubebuilder:validation:Optional
	AddHeaders map[string]*string `json:"addHeaders,omitempty" tf:"add_headers,omitempty"`

	// +kubebuilder:validation:Optional
	BisoAdminControls []BisoAdminControlsParameters `json:"bisoAdminControls,omitempty" tf:"biso_admin_controls,omitempty"`

	// +kubebuilder:validation:Optional
	BlockPageEnabled *bool `json:"blockPageEnabled,omitempty" tf:"block_page_enabled,omitempty"`

	// +kubebuilder:validation:Optional
	BlockPageReason *string `json:"blockPageReason,omitempty" tf:"block_page_reason,omitempty"`

	// +kubebuilder:validation:Optional
	CheckSession []CheckSessionParameters `json:"checkSession,omitempty" tf:"check_session,omitempty"`

	// +kubebuilder:validation:Optional
	InsecureDisableDNSSECValidation *bool `json:"insecureDisableDnssecValidation,omitempty" tf:"insecure_disable_dnssec_validation,omitempty"`

	// +kubebuilder:validation:Optional
	L4Override []L4OverrideParameters `json:"l4override,omitempty" tf:"l4override,omitempty"`

	// +kubebuilder:validation:Optional
	OverrideHost *string `json:"overrideHost,omitempty" tf:"override_host,omitempty"`

	// +kubebuilder:validation:Optional
	OverrideIps []*string `json:"overrideIps,omitempty" tf:"override_ips,omitempty"`
}

// RuleSpec defines the desired state of Rule
type RuleSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     RuleParameters `json:"forProvider"`
}

// RuleStatus defines the observed state of Rule.
type RuleStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        RuleObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Rule is the Schema for the Rules API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type Rule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RuleSpec   `json:"spec"`
	Status            RuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RuleList contains a list of Rules
type RuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Rule `json:"items"`
}

// Repository type metadata.
var (
	Rule_Kind             = "Rule"
	Rule_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Rule_Kind}.String()
	Rule_KindAPIVersion   = Rule_Kind + "." + CRDGroupVersion.String()
	Rule_GroupVersionKind = CRDGroupVersion.WithKind(Rule_Kind)
)

func init() {
	SchemeBuilder.Register(&Rule{}, &RuleList{})
}
