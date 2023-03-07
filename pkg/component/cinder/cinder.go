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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubeclipper/kubeclipper/pkg/component"
	"github.com/kubeclipper/kubeclipper/pkg/component/common"
	"github.com/kubeclipper/kubeclipper/pkg/component/utils"
	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
	"github.com/kubeclipper/kubeclipper/pkg/utils/fileutil"
	"github.com/kubeclipper/kubeclipper/pkg/utils/strutil"
	tmplutil "github.com/kubeclipper/kubeclipper/pkg/utils/template"
)

func init() {
	c := &Cinder{}

	if err := component.Register(fmt.Sprintf(component.RegisterFormat, name, version), c); err != nil {
		panic(err)
	}

	if err := component.RegisterTemplate(fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, cinder), c); err != nil {
		panic(err)
	}

	if err := initI18nForComponentMeta(); err != nil {
		panic(err)
	}
}

var (
	_ component.Interface      = (*Cinder)(nil)
	_ component.TemplateRender = (*Cinder)(nil)
)

const (
	cinder        = "cinder"
	name          = "cinder"
	version       = "v1"
	namespace     = "kube-system"
	scName        = "cinder"
	reclaimPolicy = "Delete"

	manifestDir = "/tmp/.cinder"
	cinderFile  = "cinder.yaml"

	AgentImageLoader = "ImageLoader"
)

type Cinder struct {
	ImageRepoMirror string `json:"imageRepoMirror"` //optional
	IsDefault       bool   `json:"isDefaultSC"`
	Namespace       string `json:"namespace"`
	Replicas        int    `json:"replicas"`
	Version         string `json:"version"` // required

	// storage class option
	BackendType      string `json:"backendType"`
	AvailabilityZone string `json:"availabilityZone"`
	StorageClassName string `json:"storageClassName"`
	ReclaimPolicy    string `json:"reclaimPolicy"`

	// cloud.conf
	Username  string `json:"username"`
	Password  string `json:"password"`
	AuthURL   string `json:"authUrl"`
	ProjectID string `json:"projectID"`
	DomainID  string `json:"domainID"`
	Region    string `json:"region"`
	CaCert    string `json:"caCert"`

	KeyStoneEnableTLS bool `json:"-"`

	// the content of cloud.conf needs to be base64 encoded
	CloudConf string `json:"-"`

	installSteps, uninstallSteps, upgradeSteps []v1.Step
}

func (receiver Cinder) Ns() string {
	return receiver.Namespace
}

func (receiver Cinder) Svc() string {
	return ""
}

func (receiver Cinder) RequestPath() string {
	return ""
}

func (receiver Cinder) Supported() bool {
	return false
}

func (receiver Cinder) GetInstanceName() string {
	return scName
}

func (receiver Cinder) Validate() error {
	return nil
}

func (receiver *Cinder) InitSteps(ctx context.Context) error {
	metadata := component.GetExtraMetadata(ctx)
	receiver.Replicas = len(metadata.Masters.GetNodeIDs())
	stepAllNodes := utils.UnwrapNodeList(metadata.GetAllNodes())
	//master0 := metadata.Masters[:1]
	stepMaster0 := utils.UnwrapNodeList(metadata.Masters[:1])

	// when the component does not specify an ImageRepoMirror, the cluster LocalRegistry is inherited
	if receiver.ImageRepoMirror == "" {
		receiver.ImageRepoMirror = metadata.LocalRegistry
	}
	if metadata.Offline && receiver.ImageRepoMirror == "" {
		imager := &common.Imager{
			PkgName: cinder,
			Version: receiver.Version,
			CriName: metadata.CRI,
			Offline: metadata.Offline,
		}
		steps, err := imager.InstallSteps(metadata.GetAllNodes())
		if err != nil {
			return err
		}
		receiver.installSteps = append(receiver.installSteps, steps...)
	}

	bytes, err := json.Marshal(receiver)
	if err != nil {
		return err
	}

	rs := v1.Step{
		ID:         strutil.GetUUID(),
		Name:       "renderCinderCSIManifests",
		Timeout:    metav1.Duration{Duration: 10 * time.Second},
		ErrIgnore:  false,
		RetryTimes: 1,
		Nodes:      stepMaster0,
		Action:     v1.ActionInstall,
		Commands: []v1.Command{
			{
				Type: v1.CommandTemplateRender,
				Template: &v1.TemplateCommand{
					Identity: fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, cinder),
					Data:     bytes,
				},
			},
		},
	}

	// install
	receiver.installSteps = append(receiver.installSteps, rs)

	receiver.installSteps = append(receiver.installSteps,
		v1.Step{
			ID:         strutil.GetUUID(),
			Name:       "mkdirCaDir",
			Timeout:    metav1.Duration{Duration: 10 * time.Second},
			ErrIgnore:  false,
			RetryTimes: 1,
			Nodes:      stepAllNodes,
			Action:     v1.ActionInstall,
			Commands: []v1.Command{
				{
					Type:         v1.CommandShell,
					ShellCommand: []string{"bash", "-c", "mkdir -p /etc/pki/ca-trust/source/anchors"},
				},
			},
		},
		v1.Step{
			ID:         strutil.GetUUID(),
			Name:       "deployCinderCSI",
			Timeout:    metav1.Duration{Duration: 10 * time.Second},
			ErrIgnore:  false,
			RetryTimes: 1,
			Nodes:      stepMaster0,
			Action:     v1.ActionInstall,
			Commands: []v1.Command{
				{
					Type:         v1.CommandShell,
					ShellCommand: []string{"kubectl", "apply", "-f", filepath.Join(manifestDir, cinderFile)},
				},
			},
		})

	c := new(common.CSIHealthCheck)
	checkCSIHealthStep, err := c.GetCheckCSIHealthStep(stepMaster0, receiver.StorageClassName)
	if err != nil {
		return err
	}
	receiver.installSteps = append(receiver.installSteps, checkCSIHealthStep...)

	// TODO: uninstall
	if metadata.OperationType != v1.OperationDeleteCluster {
		receiver.uninstallSteps = append(receiver.uninstallSteps,
			rs,
			v1.Step{
				ID:         strutil.GetUUID(),
				Name:       "uninstallCinderCSI",
				Nodes:      stepMaster0,
				Action:     v1.ActionUninstall,
				Timeout:    metav1.Duration{Duration: 10 * time.Second},
				ErrIgnore:  false,
				RetryTimes: 0,
				Commands: []v1.Command{
					{
						Type:         v1.CommandShell,
						ShellCommand: []string{"kubectl", "delete", "-f", filepath.Join(manifestDir, cinderFile)},
					},
				},
			})
	}

	// TODO: upgrade

	return nil
}

func (receiver *Cinder) GetName() string {
	return name
}

func (receiver *Cinder) GetComponentMeta(lang component.Lang) component.Meta {
	loc := component.GetLocalizer(lang)
	f := component.JSON(false)
	propMap := map[string]component.JSONSchemaProps{
		"version": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.version"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      component.JSON("v1.23"),
			Description:  "Cinder CSI verion",
			Priority:     2,
			Dependencies: []string{"enabled"},
			EnumNames:    []string{"v1.23"},
			Enum:         []component.JSON{"v1.23"},
		},
		"authUrl": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.authUrl"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Description:  "Openstack Keystone url. example: https://127.0.0.1:5000 or https://127.0.0.1:5000/v3 or http://127.0.0.1:5000",
			Priority:     3,
			Dependencies: []string{"enabled"},
		},
		"username": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.username"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Description:  "openstack user name",
			Priority:     4,
			Dependencies: []string{"enabled"},
		},
		"password": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.password"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Mask:         true,
			Description:  "openstack user password",
			Priority:     5,
			Dependencies: []string{"enabled"},
		},
		"projectID": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.projectID"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Description:  "openstack project ID",
			Priority:     6,
			Dependencies: []string{"enabled"},
		},
		"domainID": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.domainID"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Description:  "domain ID",
			Priority:     7,
			Dependencies: []string{"enabled"},
		},
		"region": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.region"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Description:  "openstack region",
			Priority:     8,
			Dependencies: []string{"enabled"},
		},
		"caCert": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.caCert"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Description:  "openstack full chain ca cert",
			Priority:     9,
			Mask:         true,
			Dependencies: []string{"enabled"},
		},
		"availabilityZone": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.availabilityZone"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      component.JSON("nova"),
			Description:  "openstack cinder availability zone. example: nova",
			Priority:     10,
			Dependencies: []string{"enabled"},
		},
		"backendType": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.backendType"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Description:  "openstack cinder backend type. example: __DEFAULT__",
			Priority:     11,
			Dependencies: []string{"enabled"},
		},
		"scName": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.scName"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      component.JSON(scName),
			Description:  "Storage Class name",
			Priority:     12,
			Dependencies: []string{"enabled"},
		},
		"reclaimPolicy": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.reclaimPolicy"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      component.JSON(reclaimPolicy),
			Description:  "Storage Class reclaim policy",
			Priority:     13,
			Dependencies: []string{"enabled"},
			EnumNames:    []string{"Retain", "Delete"},
			Enum:         []component.JSON{"Retain", "Delete"},
		},
		"isDefaultSC": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.isDefaultSC"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeBool,
			Default:      f,
			Description:  "set as default Storage Class",
			Priority:     14,
			Dependencies: []string{"enabled"},
		},
		"replicas": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.replicas"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeInt,
			Default:      component.JSON(1),
			Description:  "cinder provisioner replicas. It should only run on the master nodes",
			Priority:     11,
			Dependencies: []string{"enabled"},
		},
		"imageRepoMirror": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.imageRepoMirror"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Description:  "cinder image repository mirror, the component official repository is used by default",
			Priority:     12,
			Dependencies: []string{"enabled"},
		},
	}
	return component.Meta{
		Title:      loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "cinder.metaTitle"}),
		Name:       name,
		Version:    version,
		Unique:     true,
		Template:   true,
		Dependence: []string{component.InternalCategoryKubernetes},
		Category:   component.InternalCategoryStorage,
		Priority:   3,
		Schema: &component.JSONSchemaProps{
			Properties: propMap,
			Required:   []string{"authUrl", "username", "password", "projectID", "domainID", "region", "caCert", "availabilityZone", "backendType", "scName"},
			Type:       component.JSONSchemaTypeObject,
			Default:    nil,
		},
	}
}

func (receiver *Cinder) NewInstance() component.ObjectMeta {
	return &Cinder{
		Namespace:        namespace,
		StorageClassName: scName,
		ReclaimPolicy:    reclaimPolicy,
	}
}

func (receiver *Cinder) GetDependence() []string {
	return []string{component.InternalCategoryKubernetes}
}

func (receiver *Cinder) GetInstallSteps() []v1.Step {
	return receiver.installSteps
}

func (receiver *Cinder) GetUninstallSteps() []v1.Step {
	return receiver.uninstallSteps
}

func (receiver *Cinder) GetUpgradeSteps() []v1.Step {
	return receiver.upgradeSteps
}

func (receiver *Cinder) manifestsRenderTo(w io.Writer) error {
	at := tmplutil.New()
	_, err := at.RenderTo(w, manifestsTemplate, receiver)
	return err
}

func (receiver *Cinder) Render(ctx context.Context, opts component.Options) error {
	// storage namespace
	receiver.Namespace = namespace
	receiver.KeyStoneEnableTLS = strings.HasPrefix(receiver.AuthURL, "https")

	cloudConf, err := tmplutil.New().Render(cloudConfTemplate, receiver)
	if err != nil {
		return err
	}

	receiver.CloudConf = base64.URLEncoding.EncodeToString([]byte(cloudConf))

	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		return err
	}
	manifestsFile := filepath.Join(manifestDir, cinderFile)

	return fileutil.WriteFileWithContext(ctx, manifestsFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644,
		receiver.manifestsRenderTo, opts.DryRun)
}

func (receiver *Cinder) RequireExtraCluster() []string {
	return nil
}

func (receiver *Cinder) CompleteWithExtraCluster(extra map[string]component.ExtraMetadata) error {
	return nil
}

func (receiver *Cinder) GetImageRepoMirror() string {
	return receiver.ImageRepoMirror
}
