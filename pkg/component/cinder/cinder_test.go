/*
 *
 *  * Copyright 2021 KubeClipper Authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package cinder

import (
	"context"
	"testing"

	"github.com/kubeclipper/kubeclipper/pkg/component"
	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
)

func TestCinder_Render(t *testing.T) {
	type fields struct {
		ImageRegistry     string
		IsDefault         bool
		Namespace         string
		BackendType       string
		AvailabilityZone  string
		StorageClassName  string
		ReclaimPolicy     string
		Username          string
		Password          string
		AuthURL           string
		ProjectID         string
		DomainID          string
		Region            string
		KeyStoneEnableTLS bool
		CloudConf         string
		installSteps      []v1.Step
		uninstallSteps    []v1.Step
		upgradeSteps      []v1.Step
	}
	type args struct {
		ctx  context.Context
		opts component.Options
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "base",
			fields: fields{
				ImageRegistry:    "127.0.0.1:5000",
				IsDefault:        true,
				Namespace:        "kube-system",
				BackendType:      "__DEFAULT__",
				AvailabilityZone: "nova",
				StorageClassName: "csi-sc-cinderplugin",
				ReclaimPolicy:    "Delete",
				Username:         "test_user_name",
				Password:         "dGVzdC1wYXNzd29yZA==",
				AuthURL:          "https://cloud.com:5000",
				ProjectID:        "927331afac2843af8be433d4e3893678",
				DomainID:         "default",
				Region:           "RegionOne",
			},
			args: args{
				ctx:  context.TODO(),
				opts: component.Options{DryRun: false},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receiver := &Cinder{
				ImageRepoMirror:   tt.fields.ImageRegistry,
				IsDefault:         tt.fields.IsDefault,
				Namespace:         tt.fields.Namespace,
				BackendType:       tt.fields.BackendType,
				AvailabilityZone:  tt.fields.AvailabilityZone,
				StorageClassName:  tt.fields.StorageClassName,
				ReclaimPolicy:     tt.fields.ReclaimPolicy,
				Username:          tt.fields.Username,
				Password:          tt.fields.Password,
				AuthURL:           tt.fields.AuthURL,
				ProjectID:         tt.fields.ProjectID,
				DomainID:          tt.fields.DomainID,
				Region:            tt.fields.Region,
				KeyStoneEnableTLS: tt.fields.KeyStoneEnableTLS,
				CloudConf:         tt.fields.CloudConf,
				installSteps:      tt.fields.installSteps,
				uninstallSteps:    tt.fields.uninstallSteps,
				upgradeSteps:      tt.fields.upgradeSteps,
			}
			if err := receiver.Render(tt.args.ctx, tt.args.opts); (err != nil) != tt.wantErr {
				t.Errorf("Render() error = %v, wantErr %v", err, tt.wantErr)
			} else {
				t.Logf("Render() run succesfully")
			}
		})
	}
}
