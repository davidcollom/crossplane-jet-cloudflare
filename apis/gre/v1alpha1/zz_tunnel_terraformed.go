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
	"github.com/pkg/errors"

	"github.com/crossplane/terrajet/pkg/resource"
	"github.com/crossplane/terrajet/pkg/resource/json"
<<<<<<< HEAD
	
=======
>>>>>>> 205d351
)

// GetTerraformResourceType returns Terraform resource type for this Tunnel
func (mg *Tunnel) GetTerraformResourceType() string {
	return "cloudflare_gre_tunnel"
}

// GetConnectionDetailsMapping for this Tunnel
func (tr *Tunnel) GetConnectionDetailsMapping() map[string]string {
<<<<<<< HEAD
  return nil
=======
	return nil
>>>>>>> 205d351
}

// GetObservation of this Tunnel
func (tr *Tunnel) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this Tunnel
func (tr *Tunnel) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this Tunnel
func (tr *Tunnel) GetID() string {
<<<<<<< HEAD
    if tr.Status.AtProvider.ID == nil {
        return ""
    }
    return *tr.Status.AtProvider.ID
=======
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
>>>>>>> 205d351
}

// GetParameters of this Tunnel
func (tr *Tunnel) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this Tunnel
func (tr *Tunnel) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this Tunnel using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *Tunnel) LateInitialize(attrs []byte) (bool, error) {
	params := &TunnelParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}
<<<<<<< HEAD
	
=======
>>>>>>> 205d351

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *Tunnel) GetTerraformSchemaVersion() int {
<<<<<<< HEAD
    return 0
=======
	return 0
>>>>>>> 205d351
}
