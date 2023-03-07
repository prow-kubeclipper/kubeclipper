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

package cephcsi

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/kubeclipper/kubeclipper/pkg/component/validation"
	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
	"github.com/kubeclipper/kubeclipper/pkg/utils/fileutil"
	"github.com/kubeclipper/kubeclipper/pkg/utils/netutil"
	"github.com/kubeclipper/kubeclipper/pkg/utils/strutil"
	tmplutil "github.com/kubeclipper/kubeclipper/pkg/utils/template"
)

func init() {
	cc := &CephCSI{}
	if err := component.Register(fmt.Sprintf(component.RegisterFormat, name, version), cc); err != nil {
		panic(err)
	}

	if err := component.RegisterTemplate(fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, ceph), cc); err != nil {
		panic(err)
	}

	//if err := component.RegisterAgentStep(fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, AgentImageLoader), &ImageLoader{}); err != nil {
	//	panic(err)
	//}
	if err := initI18nForComponentMeta(); err != nil {
		panic(err)
	}
}

var (
	_ component.Interface      = (*CephCSI)(nil)
	_ component.TemplateRender = (*CephCSI)(nil)
	//_ component.StepRunnable   = (*ImageLoader)(nil)
)

const (
	ceph             = "ceph"
	name             = "ceph-csi"
	version          = "v1"
	namespace        = "kube-system"
	manifestsDir     = "/usr/share/kc"
	cephCSIFile      = "cephcsi.yaml"
	namespaceFile    = "namespace.yaml"
	scName           = "ceph-rbd-sc"
	fsType           = "ext4"
	reclaimPolicy    = "Delete"
	AgentImageLoader = "ImageLoader"
)

type (
	CSIConfig struct {
		// ClusterID is used for unique identification
		CephClusterID string `json:"clusterID"` // required
		// Monitors is monitor list for corresponding cluster ID
		CephMonitors []string `json:"monitors"` // required
	}
	CephCSI struct {
		ImageRepoMirror                            string `json:"imageRepoMirror"` // optional
		Namespace                                  string `json:"namespace"`       // optional
		Replicas                                   int    `json:"replicas"`
		ManifestsDir                               string `json:"manifestsDir"` // optional
		CSIConfig                                  `json:",inline"`
		UserID                                     string `json:"userID"`        // required
		UserKey                                    string `json:"userKey"`       // required
		PoolID                                     string `json:"poolID"`        // required
		StorageClassName                           string `json:"scName"`        // optional
		IsDefault                                  bool   `json:"isDefaultSC"`   // optional
		ReclaimPolicy                              string `json:"reclaimPolicy"` // optional
		FsType                                     string `json:"fsType"`        // optional
		installSteps, uninstallSteps, upgradeSteps []v1.Step
	}
)

var (
	errEmptyCephClusterID  = errors.New("Ceph Cluster ID must be provided")
	errEmptyCephMonitors   = errors.New("Ceph monitors must be provided")
	errInvalidCephMonitors = errors.New("invalid Ceph monitors")
	errEmptyUserID         = errors.New("Ceph user ID must be provided")
	errEmptyPoolID         = errors.New("Ceph pool ID must be provided")
	errInvalidFSType       = errors.New("invalid file system type")
)

func (cc CSIConfig) Validate() error {
	// ceph cluster ID
	if cc.CephClusterID == "" {
		return errEmptyCephClusterID
	}
	// ceph monitors
	if len(cc.CephMonitors) == 0 {
		return errEmptyCephMonitors
	}
	for _, mon := range cc.CephMonitors {
		ip := mon
		if strings.Contains(mon, ":") && mon[0:1] != ":" {
			arr := strings.Split(mon, ":")
			if len(arr) == 0 {
				return errInvalidCephMonitors
			}
			ip = arr[0]
		}

		if !netutil.IsValidIP(ip) {
			return errInvalidCephMonitors
		}
	}
	return nil
}

func (cc *CephCSI) Validate() error {
	// namespace
	if !validation.MatchKubernetesNamespace(cc.Namespace) {
		return validation.ErrInvalidNamespace
	}
	// CSI config
	if err := cc.CSIConfig.Validate(); err != nil {
		return err
	}
	// user ID
	if cc.UserID == "" {
		return errEmptyUserID
	}
	// pool ID
	if cc.PoolID == "" {
		return errEmptyPoolID
	}
	// storage class name
	if !validation.MatchKubernetesStorageClass(cc.StorageClassName) {
		return validation.ErrInvalidSCName
	}
	// reclaim policy
	if err := validation.MatchKubernetesReclaimPolicy(cc.ReclaimPolicy); err != nil {
		return err
	}
	// fs type
	if !isValidFSType(cc.FsType) {
		return errInvalidFSType
	}
	return nil
}

func (cc *CephCSI) InitSteps(ctx context.Context) error {
	metadata := component.GetExtraMetadata(ctx)
	// master0 := metadata.Masters[:1]
	stepMaster0 := utils.UnwrapNodeList(metadata.Masters[:1])
	// when the component does not specify an ImageRepoMirror, the cluster LocalRegistry is inherited
	if cc.ImageRepoMirror == "" {
		cc.ImageRepoMirror = metadata.LocalRegistry
	}
	if metadata.Offline && cc.ImageRepoMirror == "" {
		// TODO: version can be configured
		imager := &common.Imager{
			PkgName: ceph,
			Version: "v3.4.0",
			CriName: metadata.CRI,
			Offline: metadata.Offline,
		}
		steps, err := imager.InstallSteps(metadata.GetAllNodes())
		if err != nil {
			return err
		}
		cc.installSteps = append(cc.installSteps, steps...)
	}

	bytes, err := json.Marshal(cc)
	if err != nil {
		return err
	}

	step := v1.Step{
		ID:         strutil.GetUUID(),
		Name:       "renderCephCSIManifests",
		Timeout:    metav1.Duration{Duration: 10 * time.Second},
		ErrIgnore:  true,
		RetryTimes: 1,
		Nodes:      stepMaster0,
		Action:     v1.ActionInstall,
		Commands: []v1.Command{
			{
				Type: v1.CommandTemplateRender,
				Template: &v1.TemplateCommand{
					Identity: fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, ceph),
					Data:     bytes,
				},
			},
		},
	}

	cc.installSteps = append(cc.installSteps,
		step,
		v1.Step{
			ID:         strutil.GetUUID(),
			Name:       "deployCephCSINameSpace",
			Timeout:    metav1.Duration{Duration: 30 * time.Second},
			ErrIgnore:  false,
			RetryTimes: 1,
			Nodes:      stepMaster0,
			Action:     v1.ActionInstall,
			Commands: []v1.Command{
				{
					Type:         v1.CommandShell,
					ShellCommand: []string{"kubectl", "apply", "-f", filepath.Join(cc.ManifestsDir, namespaceFile)},
				},
			},
		},
		v1.Step{
			ID:         strutil.GetUUID(),
			Name:       "deployCephCSI",
			Timeout:    metav1.Duration{Duration: 30 * time.Second},
			ErrIgnore:  false,
			RetryTimes: 1,
			Nodes:      stepMaster0,
			Action:     v1.ActionInstall,
			Commands: []v1.Command{
				{
					Type:         v1.CommandShell,
					ShellCommand: []string{"kubectl", "apply", "-f", filepath.Join(cc.ManifestsDir, cephCSIFile)},
				},
			},
		})

	c := new(common.CSIHealthCheck)
	checkCSIHealthStep, err := c.GetCheckCSIHealthStep(stepMaster0, cc.StorageClassName)
	if err != nil {
		return err
	}
	cc.installSteps = append(cc.installSteps, checkCSIHealthStep...)

	// uninstall
	if metadata.OperationType != v1.OperationDeleteCluster {
		cc.uninstallSteps = append(cc.uninstallSteps,
			step,
			v1.Step{
				ID:         strutil.GetUUID(),
				Name:       "removeCephCSI",
				Timeout:    metav1.Duration{Duration: 10 * time.Second},
				ErrIgnore:  true,
				RetryTimes: 1,
				Nodes:      stepMaster0,
				Action:     v1.ActionUninstall,
				Commands: []v1.Command{
					{
						Type:         v1.CommandShell,
						ShellCommand: []string{"kubectl", "delete", "-f", filepath.Join(cc.ManifestsDir, cephCSIFile)},
					},
				},
			})
	}
	return nil
}

func (cc *CephCSI) GetName() string {
	return name
}

func (cc *CephCSI) GetVersion() string {
	return version
}

func (cc *CephCSI) GetComponentMeta(lang component.Lang) component.Meta {
	loc := component.GetLocalizer(lang)
	f := component.JSON(false)
	sc := component.JSON(scName)
	fs := component.JSON(fsType)
	rp := component.JSON(reclaimPolicy)

	propMap := map[string]component.JSONSchemaProps{
		"clusterID": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.clusterID"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Description:  "Ceph cluster unique identification",
			Priority:     2,
			Dependencies: []string{"enabled"},
		},
		"monitors": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.monitors"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeArray,
			Default:      nil,
			Description:  "monitor list for corresponding cluster ID",
			Priority:     3,
			Dependencies: []string{"enabled"},
		},
		"userID": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.userID"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Description:  "user client ID",
			Priority:     4,
			Dependencies: []string{"enabled"},
		},
		"userKey": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.userKey"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Description:  "user client key",
			Priority:     5,
			Dependencies: []string{"enabled"},
		},
		"poolID": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.poolID"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Description:  "Ceph pool into which the RBD image shall be created",
			Priority:     6,
			Dependencies: []string{"enabled"},
		},
		"scName": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.scName"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      sc,
			Description:  "Storage Class name",
			Priority:     7,
			Dependencies: []string{"enabled"},
		},
		"isDefaultSC": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.isDefaultSC"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeBool,
			Default:      f,
			Description:  "set as default Storage Class",
			Priority:     8,
			Dependencies: []string{"enabled"},
		},
		"reclaimPolicy": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.reclaimPolicy"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      rp,
			Description:  "Storage Class reclaim policy",
			Priority:     9,
			Dependencies: []string{"enabled"},
			EnumNames:    []string{"Retain", "Delete"},
			Enum:         []component.JSON{"Retain", "Delete"},
		},
		"fsType": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.fsType"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      fs,
			Description:  "file system type. support ext4,xfs, default ext4. xfs is not recommended due to potential deadlock. more detail to: https://rook.io/docs/rook/v1.9/ceph-block.html",
			Priority:     10,
			Dependencies: []string{"enabled"},
			Enum:         []component.JSON{"ext4", "xfs"},
			EnumNames:    []string{"ext4", "xfs"},
		},
		"replicas": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.replicas"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeInt,
			Default:      component.JSON(1),
			Description:  "ceph provisioner replicas. but it will only run on the master node",
			Priority:     11,
			Dependencies: []string{"enabled"},
		},
		"imageRepoMirror": {
			Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.imageRepoMirror"}),
			Properties:   nil,
			Type:         component.JSONSchemaTypeString,
			Default:      nil,
			Description:  "ceph image repository mirror, the component official repository is used by default",
			Priority:     12,
			Dependencies: []string{"enabled"},
		},
	}
	return component.Meta{
		Title:      loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ceph.metaTitle"}),
		Name:       name,
		Version:    version,
		Unique:     true,
		Template:   true,
		Dependence: []string{component.InternalCategoryKubernetes},
		Category:   component.InternalCategoryStorage,
		Priority:   3,
		Schema: &component.JSONSchemaProps{
			Properties: propMap,
			Required:   []string{"clusterID", "monitors", "userID", "userKey", "poolID", "scName"},
			Type:       component.JSONSchemaTypeObject,
			Default:    nil,
		},
	}
}

func (cc *CephCSI) NewInstance() component.ObjectMeta {
	return &CephCSI{
		Namespace:        namespace,
		ManifestsDir:     manifestsDir,
		StorageClassName: scName,
		FsType:           fsType,
		ReclaimPolicy:    reclaimPolicy,
	}
}

func (cc *CephCSI) GetDependence() []string {
	return []string{component.InternalCategoryKubernetes}
}

func (cc *CephCSI) GetInstallSteps() []v1.Step {
	return cc.installSteps
}

func (cc *CephCSI) GetUninstallSteps() []v1.Step {
	return cc.uninstallSteps
}

func (cc *CephCSI) GetUpgradeSteps() []v1.Step {
	return cc.upgradeSteps
}

func (cc *CephCSI) renderTo(w io.Writer) error {
	at := tmplutil.New()
	_, err := at.RenderTo(w, manifestsTemplate, cc)
	return err
}

func (cc CephCSI) renderNameSpace(w io.Writer) error {
	at := tmplutil.New()
	_, err := at.RenderTo(w, nameSpaceTemplate, cc)
	return err
}

func (cc *CephCSI) Render(ctx context.Context, opts component.Options) error {
	// storage namespace
	cc.Namespace = namespace
	if err := os.MkdirAll(cc.ManifestsDir, 0755); err != nil {
		return err
	}
	nameSpace := filepath.Join(cc.ManifestsDir, namespaceFile)
	if err := fileutil.WriteFileWithContext(ctx, nameSpace, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644,
		cc.renderNameSpace, opts.DryRun); err != nil {
		return err
	}
	manifestsFile := filepath.Join(cc.ManifestsDir, cephCSIFile)
	return fileutil.WriteFileWithContext(ctx, manifestsFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644,
		cc.renderTo, opts.DryRun)
}

func (cc *CephCSI) RequireExtraCluster() []string {
	return nil
}

func (cc *CephCSI) CompleteWithExtraCluster(extra map[string]component.ExtraMetadata) error {
	return nil
}

func (cc *CephCSI) GetImageRepoMirror() string {
	return cc.ImageRepoMirror
}

//type ImageLoader struct {
//	Version string
//	CriType string
//	Offline bool
//}
//
//func (cc *ImageLoader) Install(ctx context.Context, opts component.Options) ([]byte, error) {
//	instance, err := downloader.NewInstance(ctx, ceph, cc.Version, runtime.GOARCH, !cc.Offline, opts.DryRun)
//	if err != nil {
//		return nil, err
//	}
//	dstFile, err := instance.DownloadImages()
//	if err != nil {
//		return nil, err
//	}
//	// load image package
//	if err = utils.LoadImage(ctx, opts.DryRun, dstFile, cc.CriType); err == nil {
//		logger.Info("ceph packages offline install successfully")
//	}
//	return nil, err
//}
//
//func (cc *ImageLoader) Uninstall(ctx context.Context, opts component.Options) ([]byte, error) {
//	instance, err := downloader.NewInstance(ctx, ceph, cc.Version, runtime.GOARCH, !cc.Offline, opts.DryRun)
//	if err != nil {
//		return nil, err
//	}
//	if err = instance.RemoveImages(); err != nil {
//		logger.Error("remove ceph images compressed file failed", zap.Error(err))
//	}
//	return nil, nil
//}
//
//func (cc *ImageLoader) NewInstance() component.ObjectMeta {
//	return &ImageLoader{}
//}

func isValidFSType(fsType string) bool {
	switch fsType {
	case "ext4", "xfs":
		return true
	default:
		return false
	}
}

func (cc *CephCSI) GetInstanceName() string {
	return cc.StorageClassName
}

func (cc *CephCSI) Ns() string {
	return cc.Namespace
}

func (cc *CephCSI) Svc() string {
	return ""
}

func (cc *CephCSI) RequestPath() string {
	return ""
}

func (cc *CephCSI) Supported() bool {
	return false
}
