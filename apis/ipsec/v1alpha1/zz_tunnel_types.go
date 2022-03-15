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

type TunnelObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type TunnelParameters struct {

	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// +kubebuilder:validation:Required
	CloudflareEndpoint *string `json:"cloudflareEndpoint" tf:"cloudflare_endpoint,omitempty"`

	// +kubebuilder:validation:Required
	CustomerEndpoint *string `json:"customerEndpoint" tf:"customer_endpoint,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Required
	InterfaceAddress *string `json:"interfaceAddress" tf:"interface_address,omitempty"`
}

// TunnelSpec defines the desired state of Tunnel
type TunnelSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     TunnelParameters `json:"forProvider"`
}

// TunnelStatus defines the observed state of Tunnel.
type TunnelStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        TunnelObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Tunnel is the Schema for the Tunnels API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflarejet}
type Tunnel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TunnelSpec   `json:"spec"`
	Status            TunnelStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TunnelList contains a list of Tunnels
type TunnelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tunnel `json:"items"`
}

// Repository type metadata.
var (
	Tunnel_Kind             = "Tunnel"
	Tunnel_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Tunnel_Kind}.String()
	Tunnel_KindAPIVersion   = Tunnel_Kind + "." + CRDGroupVersion.String()
	Tunnel_GroupVersionKind = CRDGroupVersion.WithKind(Tunnel_Kind)
)

func init() {
	SchemeBuilder.Register(&Tunnel{}, &TunnelList{})
}
