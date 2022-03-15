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

type AccountObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type AccountParameters struct {

	// +kubebuilder:validation:Required
	AccountID *string `json:"accountId" tf:"account_id,omitempty"`

	// +kubebuilder:validation:Optional
	ActivityLogEnabled *bool `json:"activityLogEnabled,omitempty" tf:"activity_log_enabled,omitempty"`

	// +kubebuilder:validation:Optional
	Antivirus []AntivirusParameters `json:"antivirus,omitempty" tf:"antivirus,omitempty"`

	// +kubebuilder:validation:Optional
	BlockPage []BlockPageParameters `json:"blockPage,omitempty" tf:"block_page,omitempty"`

	// +kubebuilder:validation:Optional
	Fips []FipsParameters `json:"fips,omitempty" tf:"fips,omitempty"`

	// +kubebuilder:validation:Optional
	Logging []LoggingParameters `json:"logging,omitempty" tf:"logging,omitempty"`

	// +kubebuilder:validation:Optional
	Proxy []ProxyParameters `json:"proxy,omitempty" tf:"proxy,omitempty"`

	// +kubebuilder:validation:Optional
	TLSDecryptEnabled *bool `json:"tlsDecryptEnabled,omitempty" tf:"tls_decrypt_enabled,omitempty"`

	// +kubebuilder:validation:Optional
	URLBrowserIsolationEnabled *bool `json:"urlBrowserIsolationEnabled,omitempty" tf:"url_browser_isolation_enabled,omitempty"`
}

type AntivirusObservation struct {
}

type AntivirusParameters struct {

	// +kubebuilder:validation:Required
	EnabledDownloadPhase *bool `json:"enabledDownloadPhase" tf:"enabled_download_phase,omitempty"`

	// +kubebuilder:validation:Required
	EnabledUploadPhase *bool `json:"enabledUploadPhase" tf:"enabled_upload_phase,omitempty"`

	// +kubebuilder:validation:Required
	FailClosed *bool `json:"failClosed" tf:"fail_closed,omitempty"`
}

type BlockPageObservation struct {
}

type BlockPageParameters struct {

	// +kubebuilder:validation:Optional
	BackgroundColor *string `json:"backgroundColor,omitempty" tf:"background_color,omitempty"`

	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	FooterText *string `json:"footerText,omitempty" tf:"footer_text,omitempty"`

	// +kubebuilder:validation:Optional
	HeaderText *string `json:"headerText,omitempty" tf:"header_text,omitempty"`

	// +kubebuilder:validation:Optional
	LogoPath *string `json:"logoPath,omitempty" tf:"logo_path,omitempty"`

	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`
}

type DNSObservation struct {
}

type DNSParameters struct {

	// +kubebuilder:validation:Required
	LogAll *bool `json:"logAll" tf:"log_all,omitempty"`

	// +kubebuilder:validation:Required
	LogBlocks *bool `json:"logBlocks" tf:"log_blocks,omitempty"`
}

type FipsObservation struct {
}

type FipsParameters struct {

	// +kubebuilder:validation:Optional
	TLS *bool `json:"tls,omitempty" tf:"tls,omitempty"`
}

type HTTPObservation struct {
}

type HTTPParameters struct {

	// +kubebuilder:validation:Required
	LogAll *bool `json:"logAll" tf:"log_all,omitempty"`

	// +kubebuilder:validation:Required
	LogBlocks *bool `json:"logBlocks" tf:"log_blocks,omitempty"`
}

type L4Observation struct {
}

type L4Parameters struct {

	// +kubebuilder:validation:Required
	LogAll *bool `json:"logAll" tf:"log_all,omitempty"`

	// +kubebuilder:validation:Required
	LogBlocks *bool `json:"logBlocks" tf:"log_blocks,omitempty"`
}

type LoggingObservation struct {
}

type LoggingParameters struct {

	// +kubebuilder:validation:Required
	RedactPii *bool `json:"redactPii" tf:"redact_pii,omitempty"`

	// +kubebuilder:validation:Required
	SettingsByRuleType []SettingsByRuleTypeParameters `json:"settingsByRuleType" tf:"settings_by_rule_type,omitempty"`
}

type ProxyObservation struct {
}

type ProxyParameters struct {

	// +kubebuilder:validation:Required
	TCP *bool `json:"tcp" tf:"tcp,omitempty"`

	// +kubebuilder:validation:Required
	UDP *bool `json:"udp" tf:"udp,omitempty"`
}

type SettingsByRuleTypeObservation struct {
}

type SettingsByRuleTypeParameters struct {

	// +kubebuilder:validation:Required
	DNS []DNSParameters `json:"dns" tf:"dns,omitempty"`

	// +kubebuilder:validation:Required
	HTTP []HTTPParameters `json:"http" tf:"http,omitempty"`

	// +kubebuilder:validation:Required
	L4 []L4Parameters `json:"l4" tf:"l4,omitempty"`
}

// AccountSpec defines the desired state of Account
type AccountSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     AccountParameters `json:"forProvider"`
}

// AccountStatus defines the observed state of Account.
type AccountStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        AccountObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Account is the Schema for the Accounts API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type Account struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AccountSpec   `json:"spec"`
	Status            AccountStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccountList contains a list of Accounts
type AccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Account `json:"items"`
}

// Repository type metadata.
var (
	Account_Kind             = "Account"
	Account_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Account_Kind}.String()
	Account_KindAPIVersion   = Account_Kind + "." + CRDGroupVersion.String()
	Account_GroupVersionKind = CRDGroupVersion.WithKind(Account_Kind)
)

func init() {
	SchemeBuilder.Register(&Account{}, &AccountList{})
}
