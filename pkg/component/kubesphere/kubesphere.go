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

package kubesphere

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

	"github.com/kubeclipper/kubeclipper/pkg/component/common"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kubeclipper/kubeclipper/pkg/component"
	"github.com/kubeclipper/kubeclipper/pkg/component/utils"
	"github.com/kubeclipper/kubeclipper/pkg/logger"
	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
	"github.com/kubeclipper/kubeclipper/pkg/utils/cmdutil"
	"github.com/kubeclipper/kubeclipper/pkg/utils/fileutil"
	"github.com/kubeclipper/kubeclipper/pkg/utils/strutil"
	tmplutil "github.com/kubeclipper/kubeclipper/pkg/utils/template"
)

func init() {
	c := Kubesphere{}
	if err := component.Register(fmt.Sprintf(component.RegisterFormat, name, version), &c); err != nil {
		panic(err)
	}
	if err := component.RegisterTemplate(fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, "ks"), &c); err != nil {
		panic(err)
	}
	if err := component.RegisterAgentStep(fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, "ks"), &c); err != nil {
		panic(err)
	}
	//if err := component.RegisterAgentStep(fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, AgentImageLoader), &ImageLoader{}); err != nil {
	//	panic(err)
	//}
	if err := component.RegisterAgentStep(fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, AgentCheckInstall), &CheckInstall{}); err != nil {
		panic(err)
	}
	if err := component.RegisterAgentStep(fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, AgentRegisterCluster), &RegisterCluster{}); err != nil {
		panic(err)
	}
	if err := initI18nForComponentMeta(); err != nil {
		panic(err)
	}
}

var (
	_ component.Interface      = (*Kubesphere)(nil)
	_ component.TemplateRender = (*Kubesphere)(nil)
	//_ component.StepRunnable   = (*ImageLoader)(nil)
	_ component.StepRunnable = (*CheckInstall)(nil)
	_ component.StepRunnable = (*RegisterCluster)(nil)
)

const (
	manifestDir            = "/tmp/.ks"
	ks                     = "kubesphere"
	name                   = "kubesphere"
	version                = "v1"
	ksUninstallFile        = "ks-uninstall.sh"
	ksInstallerFile        = "ks-installer.yaml"
	clusterConfFile        = "cluster-configuration.yaml"
	ksExtensionInstallFile = "ks-extension-install.yaml"
	AgentImageLoader       = "ImageLoader"
	AgentCheckInstall      = "CheckInstall"
	AgentRegisterCluster   = "RegisterCluster"
)

const (
	clusterRoleHost   = "host"
	clusterRoleMember = "member"
	clusterRoleNone   = "none"
	clusterTypeProd   = "production"
	clusterTypeTest   = "testing"
	clusterTypeDemo   = "demo"
	clusterTypeDevel  = "development"
)

type Kubesphere struct {
	ImageRepoMirror string               `json:"imageRepoMirror"` // optional
	JwtSecret       string               `json:"jwtSecret"`
	Version         string               `json:"version"`
	ClusterRole     string               `json:"clusterRole"`
	ClusterType     string               `json:"clusterType"`
	HostClusterName string               `json:"hostClusterName,omitempty"`
	StorageClass    string               `json:"storageClass"`
	Console         *ConsoleConfig       `json:"console,omitempty"`
	Monitor         *MonitorConfig       `json:"monitor,omitempty"`
	Es              *ElasticSearchConfig `json:"es,omitempty"`
	Plugin          *PluginConfig        `json:"plugin,omitempty"`
	hostClusterMeta component.ExtraMetadata
	installSteps    []v1.Step
	uninstallSteps  []v1.Step
	upgradeSteps    []v1.Step
	// Event              *EventsConfig        `json:"event,omitempty"`
	// Devops             *DevOpsConfig        `json:"devops,omitempty"`
	// Logging            *LoggingConfig       `json:"logging,omitempty"`
	// Alert              *AlertingConfig      `json:"alert,omitempty"`
	// Network            *NetworkConfig       `json:"network,omitempty"`
}

func (i *Kubesphere) Ns() string {
	return "kubesphere-system"
}

func (i *Kubesphere) Svc() string {
	return "ks-apiserver"
}

func (i *Kubesphere) RequestPath() string {
	return "kapis/version"
}

func (i *Kubesphere) Supported() bool {
	return true
}

func (i *Kubesphere) GetInstanceName() string {
	return name
}

type PluginConfig struct {
	EnableEvent        bool `json:"enableEvent"`
	EnableDevops       bool `json:"enableDevops"`
	EnableLogging      bool `json:"enableLogging"`
	EnableAlert        bool `json:"enableAlert"`
	EnableNetwork      bool `json:"enableNetwork"`
	EnableAudit        bool `json:"enableAudit"`
	EnableMetricServer bool `json:"enableMetricServer"`
	EnableServiceMesh  bool `json:"enableServiceMesh"`
	EnableAppStore     bool `json:"enableAppStore"`
}

type ConsoleConfig struct {
	EnableMultiLogin bool `json:"enableMultiLogin"`
	Port             int  `json:"port"`
}

type ElasticSearchConfig struct {
	ElasticsearchMasterReplicas   int    `json:"elasticsearchMasterReplicas,omitempty" validate:"omitempty,gte=1" description:"total number of master nodes, it's not allowed to use even number"`
	ElasticsearchDataReplicas     int    `json:"elasticsearchDataReplicas,omitempty" validate:"omitempty,gte=1" description:"total number of data nodes."`
	ElasticsearchMasterVolumeSize string `json:"elasticsearchMasterVolumeSize" description:"Volume size of Elasticsearch master nodes."`
	ElasticsearchDataVolumeSize   string `json:"elasticsearchDataVolumeSize" description:"Volume size of Elasticsearch data nodes."`
	LogMaxAge                     int    `json:"logMaxAge,omitempty" validate:"omitempty,gte=1" description:"Log retention time in built-in Elasticsearch, it is 7 days by default."`
	ElkPrefix                     string `json:"elkPrefix,omitempty" validate:"omitempty" enum:"logstash" description:"The string making up index names. The index name will be formatted as ks-<elk_prefix>-log."`
}

type MonitorConfig struct {
	PrometheusReplicas    int    `json:"prometheusReplicas,omitempty" validate:"omitempty,gte=1" description:"Prometheus replicas are responsible for monitoring different segments of data source and provide high availability as well."`
	PrometheusMemoryLimit string `json:"prometheusMemoryLimit,omitempty" description:"Prometheus request memory."`
	PrometheusVolumeSize  string `json:"prometheusVolumeSize,omitempty" description:"Prometheus PVC size."`
	PrometheusCPULimit    string `json:"prometheusCPULimit,omitempty" description:"Prometheus cpu limit."`
	AlertManagerReplicas  int    `json:"alertManagerReplicas,omitempty" validate:"omitempty,gte=1" description:"AlertManager Replicas."`
	// MonitoringEndpoint      string `json:"monitoringEndpoint" description:"prometheus endpoint address"`
}

type EventsConfig struct {
	Enabled       bool `json:"enabled" description:"enable"`
	RulerReplicas int  `json:"rulerReplicas" validate:"omitempty,gte=1" description:"replicas"`
}

type DevOpsConfig struct {
	Enabled               bool   `json:"enabled" description:"enable"`
	JenkinsMemoryLimit    string `json:"jenkinsMemoryLimit,omitempty" description:"Jenkins memory limit."`
	JenkinsMemoryRequest  string `json:"jenkinsMemoryRequest,omitempty" description:"Jenkins memory request."`
	JenkinsVolumeSize     string `json:"jenkinsVolumeSize,omitempty" description:"Jenkins volume size."`
	JenkinsJavaOptsXms    string `json:"jenkinsJavaOptsXms,omitempty" description:"The following three fields are JVM parameters."`
	JenkinsJavaOptsXmx    string `json:"jenkinsJavaOptsXmx,omitempty" description:"jenkinsJavaOpts_Xmx"`
	JenkinsJavaOptsMaxRAM string `json:"jenkinsJavaOptsMaxRAM,omitempty" description:"jenkinsJavaOpts_MaxRAM"`
}

type LoggingConfig struct {
	Enabled            bool `json:"enabled" description:"enable"`
	LogSidecarReplicas int  `json:"logSidecarReplicas,omitempty" validate:"omitempty,gte=1" description:"logsidecar replicas"`
}

type AlertingConfig struct {
	Enabled            bool `json:"enabled" description:"enable"`
	ThanosRulerReplica int  `json:"thanosRulerReplica"`
}

type NetworkConfig struct {
	EnableNetworkPolicy bool   `json:"enableNetworkPolicy" description:"Network policies allow network isolation within the same cluster, which means firewalls can be set up between certain instances (Pods). Make sure that the CNI network plugin used by the cluster supports NetworkPolicy. There are a number of CNI network plugins that support NetworkPolicy, including Calico, Cilium, Kube-router, Romana and Weave Net."`
	IPPool              string `json:"IPPool,omitempty" description:"if calico cni is integrated then use the value calico, none means that the ippool function is disabled"`
	NetworkTopology     string `json:"networkTopology,omitempty" description:"only support weave-scope"`
}

func (i *Kubesphere) NewInstance() component.ObjectMeta {
	return &Kubesphere{
		Console: &ConsoleConfig{},
		Monitor: &MonitorConfig{},
		Es:      &ElasticSearchConfig{},
		Plugin:  &PluginConfig{},
	}
}

func (i *Kubesphere) GetDependence() []string {
	return []string{"kubernetes", "storage"}
}

func (i *Kubesphere) Validate() error {
	return nil
}

func (i *Kubesphere) InitSteps(ctx context.Context) error {
	extraMetadata := component.GetExtraMetadata(ctx)
	if len(extraMetadata.Masters) == 0 {
		return fmt.Errorf("init step error, cluster contains at least one master node")
	}
	// record the original image repo mirror
	ksImageRepoMirror := i.ImageRepoMirror
	if i.ImageRepoMirror == "" {
		i.ImageRepoMirror = extraMetadata.LocalRegistry
	}
	if err := i.initInstallSteps(extraMetadata, ksImageRepoMirror); err != nil {
		return err
	}
	if err := i.initUninstallSteps(extraMetadata); err != nil {
		return err
	}
	return i.initUpgradeSteps(extraMetadata)
}

func (i *Kubesphere) initInstallSteps(metadata component.ExtraMetadata, ksImageRepoMirror string) error {
	if len(i.installSteps) != 0 {
		return nil
	}
	// inject JwtSecret from host cluster into member cluster
	if i.HostClusterName != "" && len(i.hostClusterMeta.Masters) > 0 {
		i.JwtSecret = i.hostClusterMeta.KsJwtSecret
	}
	ksData, err := json.Marshal(i)
	if err != nil {
		return err
	}

	if metadata.Offline && i.ImageRepoMirror == "" {
		policy := KsImagePullPolicy{plugin: i.Plugin}
		imager := &common.Imager{
			PkgName:         ks,
			Version:         i.Version,
			CriName:         metadata.CRI,
			Offline:         metadata.Offline,
			CustomImageList: policy.ImageFiles(),
		}
		steps, err := imager.InstallSteps(metadata.GetAllNodes())
		if err != nil {
			return err
		}
		i.installSteps = append(i.installSteps, steps...)
	}

	stepMaster0 := utils.UnwrapNodeList(metadata.Masters[:1])
	i.installSteps = append(i.installSteps, []v1.Step{
		{
			ID:         strutil.GetUUID(),
			Name:       "renderKubesphereConfig",
			Timeout:    metav1.Duration{Duration: 3 * time.Minute},
			ErrIgnore:  false,
			RetryTimes: 1,
			Nodes:      stepMaster0,
			Action:     v1.ActionInstall,
			Commands: []v1.Command{
				{
					Type: v1.CommandTemplateRender,
					Template: &v1.TemplateCommand{
						Identity: fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, "ks"),
						Data:     ksData,
					},
				},
			},
		},
		{
			ID:         strutil.GetUUID(),
			Name:       "applyKubesphereConfig",
			Timeout:    metav1.Duration{Duration: 3 * time.Minute},
			ErrIgnore:  false,
			RetryTimes: 1,
			Nodes:      stepMaster0,
			Action:     v1.ActionInstall,
			Commands: []v1.Command{
				{
					Type:         v1.CommandShell,
					ShellCommand: []string{"kubectl", "apply", "-f", filepath.Join(manifestDir, ksInstallerFile)},
				},
				{
					Type:         v1.CommandShell,
					ShellCommand: []string{"kubectl", "apply", "-f", filepath.Join(manifestDir, clusterConfFile)},
				},
			},
		},
	}...)

	cData, err := json.Marshal(&CheckInstall{NeedGetKubeconfig: i.HostClusterName != ""})
	if err != nil {
		return err
	}
	checkInstallStep := v1.Step{
		ID:         strutil.GetUUID(),
		Name:       "CheckInstall",
		Timeout:    metav1.Duration{Duration: 30 * time.Minute},
		ErrIgnore:  false,
		RetryTimes: 1,
		Nodes:      stepMaster0,
		Action:     v1.ActionInstall,
		Commands: []v1.Command{
			{
				Type:          v1.CommandCustom,
				Identity:      fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, AgentCheckInstall),
				CustomCommand: cData,
			},
		},
	}
	if i.ClusterRole == clusterRoleHost {
		checkInstallStep.Commands = append(checkInstallStep.Commands, v1.Command{
			Type:         v1.CommandShell,
			ShellCommand: []string{"kubectl", "label", "--overwrite", "cluster", "host", fmt.Sprintf("cluster.kubesphere.io/group=%s", i.ClusterType)},
		})
	}
	i.installSteps = append(i.installSteps, checkInstallStep)
	// work around for delete member cluster when host cluster already deleted
	// Important: The RegisterInHost step must be immediately after the CheckInstall step because it relies on the CheckInstall step's return result as an execution parameter.
	if i.HostClusterName != "" && len(i.hostClusterMeta.Masters) > 0 {
		joinCluster := RegisterCluster{
			ClusterName: metadata.ClusterName,
			ClusterType: i.ClusterType,
			// TODO: if cluster has vip, use vip instead of master ip
			ServerAddress: fmt.Sprintf("%s:6443", metadata.Masters[0].IPv4),
		}
		jData, err := json.Marshal(joinCluster)
		if err != nil {
			return err
		}
		i.installSteps = append(i.installSteps, v1.Step{
			ID:         strutil.GetUUID(),
			Name:       "RegisterInHost",
			Timeout:    metav1.Duration{Duration: 2 * time.Minute},
			ErrIgnore:  false,
			RetryTimes: 1,
			Nodes:      utils.UnwrapNodeList(i.hostClusterMeta.Masters[:1]),
			Action:     v1.ActionInstall,
			Commands: []v1.Command{
				{
					Type:          v1.CommandCustom,
					Identity:      fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, AgentRegisterCluster),
					CustomCommand: jData,
				},
			},
		})
	}
	i.installSteps = append(i.installSteps, v1.Step{
		ID:         strutil.GetUUID(),
		Name:       "applyKubesphereExtension",
		Timeout:    metav1.Duration{Duration: 30 * time.Second},
		ErrIgnore:  false,
		RetryTimes: 1,
		Nodes:      stepMaster0,
		Action:     v1.ActionInstall,
		Commands: []v1.Command{
			{
				Type: v1.CommandShell,
				ShellCommand: []string{"kubectl", "apply", "-f",
					filepath.Join(manifestDir, ksExtensionInstallFile)},
			},
		},
	})

	return nil
}

func (i *Kubesphere) initUninstallSteps(metadata component.ExtraMetadata) error {
	if len(i.uninstallSteps) != 0 {
		return nil
	}

	if metadata.OperationType == v1.OperationDeleteCluster && i.ClusterRole == clusterRoleMember && i.HostClusterName != "" {
		i.uninstallSteps = append(i.uninstallSteps, v1.Step{
			ID:         strutil.GetUUID(),
			Name:       "removeKSFedCluster",
			Timeout:    metav1.Duration{Duration: 10 * time.Minute},
			ErrIgnore:  true,
			RetryTimes: 0,
			Nodes:      utils.UnwrapNodeList(i.hostClusterMeta.Masters[:1]),
			Action:     v1.ActionUninstall,
			Commands: []v1.Command{
				{
					Type:         v1.CommandShell,
					ShellCommand: []string{"bash", "-c", fmt.Sprintf("kubectl delete cluster %s", metadata.ClusterName)},
				},
			},
		})
		return nil
	}

	if metadata.OperationType != v1.OperationDeleteCluster {
		bytes, err := json.Marshal(i)
		if err != nil {
			return err
		}

		stepMaster0 := utils.UnwrapNodeList(metadata.Masters[:1])
		rs := v1.Step{
			ID:         strutil.GetUUID(),
			Name:       "renderUninstallKubeSphere",
			Timeout:    metav1.Duration{Duration: 3 * time.Minute},
			ErrIgnore:  true,
			RetryTimes: 1,
			Nodes:      stepMaster0,
			Action:     v1.ActionUninstall,
			Commands: []v1.Command{
				{
					Type: v1.CommandTemplateRender,
					Template: &v1.TemplateCommand{
						Identity: fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, "ks"),
						Data:     bytes,
					},
				},
			},
		}

		i.uninstallSteps = append(i.uninstallSteps,
			rs,
			v1.Step{
				ID:         strutil.GetUUID(),
				Name:       "uninstallKubesphere",
				Timeout:    metav1.Duration{Duration: 20 * time.Minute},
				ErrIgnore:  false,
				RetryTimes: 0,
				Nodes:      stepMaster0,
				Action:     v1.ActionUninstall,
				Commands: []v1.Command{
					{
						Type:          v1.CommandCustom,
						Identity:      fmt.Sprintf(component.RegisterTemplateKeyFormat, name, version, "ks"),
						CustomCommand: bytes,
					},
				},
			})
	}

	return nil
}

func (i *Kubesphere) initUpgradeSteps(metadata component.ExtraMetadata) error {
	return nil
}

func (i *Kubesphere) GetInstallSteps() []v1.Step {
	return i.installSteps
}

func (i *Kubesphere) GetUninstallSteps() []v1.Step {
	return i.uninstallSteps
}

func (i *Kubesphere) GetUpgradeSteps() []v1.Step {
	return i.upgradeSteps
}

func (i *Kubesphere) GetComponentMeta(lang component.Lang) component.Meta {
	loc := component.GetLocalizer(lang)
	return component.Meta{
		Title:          loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.metaTitle"}),
		Name:           name,
		Version:        version,
		Unique:         true,
		Dependence:     []string{component.InternalCategoryKubernetes, component.InternalCategoryStorage},
		Category:       component.InternalCategoryPAAS,
		Priority:       1,
		TimeoutSeconds: 180,
		Schema: &component.JSONSchemaProps{
			Properties: map[string]component.JSONSchemaProps{
				"version": {
					Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.version"}),
					Type:        component.JSONSchemaTypeString,
					Description: "kubesphere version",
					Default:     "v3.2.1",
					Priority:    2,
				},
				"clusterRole": {
					Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.clusterRole"}),
					Type:        component.JSONSchemaTypeString,
					Description: "cluster role, host or member or none",
					Enum:        []component.JSON{clusterRoleHost, clusterRoleMember, clusterRoleNone},
					EnumNames:   []string{clusterRoleHost, clusterRoleMember, clusterRoleNone},
					Priority:    3,
				},
				"HostClusterName": {
					Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.hostClusterName"}),
					Type:         component.JSONSchemaTypeString,
					Description:  "host cluster name",
					Dependencies: []string{"clusterRole"},
					Priority:     4,
				},
				"clusterType": {
					Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.clusterType"}),
					Type:        component.JSONSchemaTypeString,
					Description: "cluster type,prod,devel etc",
					Enum:        []component.JSON{clusterTypeProd, clusterTypeDemo, clusterTypeTest, clusterTypeDevel},
					EnumNames:   []string{clusterTypeProd, clusterTypeDemo, clusterTypeTest, clusterTypeDevel},
					Priority:    5,
				},
				"jwtSecret": {
					Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.jwtSecret"}),
					Type:        component.JSONSchemaTypeString,
					Description: "JWT Token secret",
					Priority:    6,
				},
				"storageClass": {
					Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.storageClass"}),
					Type:        component.JSONSchemaTypeString,
					Description: "platform storage setting",
					Priority:    7,
				},
				"console": {
					Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.console"}),
					Type:        component.JSONSchemaTypeObject,
					Description: "kubesphere console config",
					Properties: map[string]component.JSONSchemaProps{
						"enableMultiLogin": {
							Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.console.enableMultiLogin"}),
							Description: "Enable MultiLogin",
							Type:        component.JSONSchemaTypeBool,
							Default:     true,
							Priority:    1,
						},
						"port": {
							Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.console.port"}),
							Description: "Console NodePort number",
							Type:        component.JSONSchemaTypeInt,
							Default:     30880,
							Priority:    2,
							Props: &component.Props{
								Min: 30000,
							},
						},
					},
					Priority: 8,
				},
				"monitor": {
					Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.monitor"}),
					Description: "kubesphere monitor setting",
					Type:        component.JSONSchemaTypeObject,
					Priority:    9,
					Properties: map[string]component.JSONSchemaProps{
						"prometheusReplicas": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.monitor.prometheusReplicas"}),
							Type:     component.JSONSchemaTypeInt,
							Priority: 1,
							Default:  1,
							Props: &component.Props{
								Min: 1,
							},
						},
						"prometheusMemoryLimit": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.monitor.prometheusMemoryLimit"}),
							Type:     component.JSONSchemaTypeString,
							Priority: 2,
							Default:  "16Gi",
						},
						"prometheusVolumeSize": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.monitor.prometheusVolumeSize"}),
							Type:     component.JSONSchemaTypeString,
							Priority: 3,
							Default:  "40Gi",
						},
						"prometheusCPULimit": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.monitor.prometheusCPULimit"}),
							Type:     component.JSONSchemaTypeString,
							Priority: 4,
							Default:  "4",
						},
						"alertManagerReplicas": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.monitor.alertManagerReplicas"}),
							Type:     component.JSONSchemaTypeInt,
							Priority: 5,
							Default:  1,
							Props: &component.Props{
								Min: 1,
							},
						},
					},
				},
				"es": {
					Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.es"}),
					Description: "kubesphere es setting",
					Type:        component.JSONSchemaTypeObject,
					Priority:    10,
					Properties: map[string]component.JSONSchemaProps{
						"elasticsearchMasterReplicas": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.es.elasticsearchMasterReplicas"}),
							Type:     component.JSONSchemaTypeInt,
							Priority: 1,
							Default:  1,
							Props: &component.Props{
								Min: 1,
							},
						},
						"elasticsearchDataReplicas": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.es.elasticsearchDataReplicas"}),
							Type:     component.JSONSchemaTypeInt,
							Priority: 2,
							Default:  1,
							Props: &component.Props{
								Min: 1,
							},
						},
						"elasticsearchMasterVolumeSize": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.es.elasticsearchMasterVolumeSize"}),
							Type:     component.JSONSchemaTypeString,
							Priority: 3,
							Default:  "10Gi",
						},
						"elasticsearchDataVolumeSize": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.es.elasticsearchDataVolumeSize"}),
							Type:     component.JSONSchemaTypeString,
							Priority: 4,
							Default:  "50Gi",
						},
						"logMaxAge": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.es.logMaxAge"}),
							Type:     component.JSONSchemaTypeInt,
							Priority: 5,
							Default:  7,
							Props: &component.Props{
								Min: 7,
							},
						},
						"elkPrefix": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.es.elkPrefix"}),
							Type:     component.JSONSchemaTypeString,
							Priority: 6,
							Default:  "logstash",
						},
					},
				},
				"plugin": {
					Title:       loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.plugin"}),
					Description: "kubesphere Plugin setting",
					Type:        component.JSONSchemaTypeObject,
					Priority:    11,
					Properties: map[string]component.JSONSchemaProps{
						"enableEvent": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.plugin.enableEvent"}),
							Type:     component.JSONSchemaTypeBool,
							Priority: 1,
							Default:  false,
						},
						"enableDevops": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.plugin.enableDevops"}),
							Type:     component.JSONSchemaTypeBool,
							Priority: 2,
							Default:  false,
						},
						"enableLogging": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.plugin.enableLogging"}),
							Type:     component.JSONSchemaTypeBool,
							Priority: 3,
							Default:  false,
						},
						"enableAlert": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.plugin.enableAlert"}),
							Type:     component.JSONSchemaTypeBool,
							Priority: 4,
							Default:  false,
						},
						"enableNetwork": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.plugin.enableNetwork"}),
							Type:     component.JSONSchemaTypeBool,
							Priority: 5,
							Default:  false,
						},
						"enableAudit": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.plugin.enableAudit"}),
							Type:     component.JSONSchemaTypeBool,
							Priority: 6,
							Default:  false,
						},
						"enableMetricServer": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.plugin.enableMetricServer"}),
							Type:     component.JSONSchemaTypeBool,
							Priority: 7,
							Default:  false,
						},
						"enableServiceMesh": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.plugin.enableServiceMesh"}),
							Type:     component.JSONSchemaTypeBool,
							Priority: 8,
							Default:  false,
						},
						"enableAppStore": {
							Title:    loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.plugin.enableAppStore"}),
							Type:     component.JSONSchemaTypeBool,
							Priority: 9,
							Default:  false,
						},
					},
				},
				"imageRepoMirror": {
					Title:        loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "ks.imageRepoMirror"}),
					Properties:   nil,
					Type:         component.JSONSchemaTypeString,
					Default:      nil,
					Description:  "ks image repository mirror, the component official repository is used by default",
					Priority:     12,
					Dependencies: []string{"enabled"},
				},
			},
			Type:     component.JSONSchemaTypeObject,
			Required: []string{"version", "clusterRole", "clusterType", "jwtSecret", "storageClass", "monitor", "es", "HostClusterName"},
		},
	}
}

func (i *Kubesphere) RequireExtraCluster() []string {
	if i.HostClusterName == "" {
		return nil
	}
	return []string{i.HostClusterName}
}

func (i *Kubesphere) CompleteWithExtraCluster(extra map[string]component.ExtraMetadata) error {
	clu, ok := extra[i.HostClusterName]
	if ok {
		i.hostClusterMeta = clu
	}
	return nil
}

func (i *Kubesphere) Render(ctx context.Context, opts component.Options) error {
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		return err
	}
	installerFile := filepath.Join(manifestDir, ksInstallerFile)
	if err := fileutil.WriteFileWithContext(ctx, installerFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644,
		i.renderInstaller, opts.DryRun); err != nil {
		return err
	}
	uninstallFile := filepath.Join(manifestDir, ksUninstallFile)
	if err := fileutil.WriteFileWithContext(ctx, uninstallFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644,
		i.renderUninstaller, opts.DryRun); err != nil {
		return err
	}
	extensionInstallFile := filepath.Join(manifestDir, ksExtensionInstallFile)
	if err := fileutil.WriteFileWithContext(ctx, extensionInstallFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644,
		i.renderExtensionServer, opts.DryRun); err != nil {
		return err
	}
	clusterConfigurationFile := filepath.Join(manifestDir, clusterConfFile)
	return fileutil.WriteFileWithContext(ctx, clusterConfigurationFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644,
		i.renderClusterConf, opts.DryRun)
}

func (i *Kubesphere) renderInstaller(w io.Writer) error {
	at := tmplutil.New()
	_, err := at.RenderTo(w, installerV3, i)
	return err
}

func (i *Kubesphere) renderClusterConf(w io.Writer) error {
	at := tmplutil.New()
	_, err := at.RenderTo(w, clusterConfV3, i)
	return err
}

func (i *Kubesphere) renderExtensionServer(w io.Writer) error {
	at := tmplutil.New()
	_, err := at.RenderTo(w, ksExtensionServer, i)
	return err
}

func (i *Kubesphere) renderUninstaller(w io.Writer) error {
	at := tmplutil.New()
	_, err := at.RenderTo(w, ksUninstallShell, i)
	return err
}

func (i *Kubesphere) Install(ctx context.Context, opts component.Options) ([]byte, error) {
	return nil, nil
}

func (i *Kubesphere) Uninstall(ctx context.Context, opts component.Options) ([]byte, error) {
	_, err := cmdutil.RunCmdWithContext(ctx, opts.DryRun, "/usr/bin/env", "bash", filepath.Join(manifestDir, ksUninstallFile))
	if err != nil {
		if ctx.Err() != nil {
			if ok := i.appendFile(ctx); ok == nil {
				return nil, nil
			}
		}
		return nil, err
	}
	return nil, nil
}

func (i *Kubesphere) appendFile(ctx context.Context) error {
	operationID := component.GetOperationID(ctx)
	stepID := component.GetStepID(ctx)
	opLog := component.GetOplog(ctx)
	path, err := opLog.GetStepLogFile(operationID, stepID)
	if err != nil {
		return err
	}
	note := "\n ===== uninstall timeout, please check if it is because finalizers field in protecting ===== \n\n"
	err = opLog.AppendLogFileContent(path, []byte(note))
	return err
}

func (i *Kubesphere) GetImageRepoMirror() string {
	return i.ImageRepoMirror
}

//
//type ImageLoader struct {
//	Version string
//	CRI     string
//	Offline bool
//	Plugin  *PluginConfig
//}
//
//func (i *ImageLoader) Install(ctx context.Context, opts component.Options) ([]byte, error) {
//	instance, err := downloader.NewInstance(ctx, ks, i.Version, runtime.GOARCH, !i.Offline, opts.DryRun)
//	if err != nil {
//		return nil, err
//	}
//	dstFiles, err := instance.DownloadCustomImages(&KsImagePullPolicy{i.Plugin})
//	if err != nil {
//		return nil, err
//	}
//	for _, dstFile := range dstFiles {
//		// load image package
//		if err = utils.LoadImage(ctx, opts.DryRun, dstFile, i.CRI); err == nil {
//			logger.Info("image tarball decompress successfully")
//		}
//	}
//	return nil, nil
//}
//
//func (i *ImageLoader) Uninstall(ctx context.Context, opts component.Options) ([]byte, error) {
//	instance, err := downloader.NewInstance(ctx, ks, i.Version, runtime.GOARCH, !i.Offline, opts.DryRun)
//	if err != nil {
//		return nil, err
//	}
//	if err = instance.RemoveCustomImages(&KsImagePullPolicy{i.Plugin}); err != nil {
//		logger.Error("remove kubesphere images compressed file failed", zap.Error(err))
//	}
//	return nil, nil
//}
//
//func (i *ImageLoader) NewInstance() component.ObjectMeta {
//	return &ImageLoader{}
//}

type CheckInstall struct {
	NeedGetKubeconfig bool
}

func (i *CheckInstall) Install(ctx context.Context, opts component.Options) ([]byte, error) {
	_, err := cmdutil.RunCmdWithContext(ctx, opts.DryRun, "bash", "-c", `kubectl delete po -n kubesphere-system  $(kubectl get pod -n kubesphere-system -l app=ks-install -o jsonpath='{.items[0].metadata.name}')`)
	if err != nil {
		logger.Warnf("delete ks-installer pod failed: %s", err.Error())
	}
	if err = utils.RetryFunc(ctx, opts, 10*time.Second, "checkKsInstall", i.checkInstall); err != nil {
		return nil, err
	}

	// read k8s cluster kubeconfig
	return os.ReadFile("/etc/kubernetes/admin.conf")
}

func (i *CheckInstall) checkInstall(ctx context.Context, opts component.Options) error {
	// kubectl logs -n kubesphere-system deploy/ks-installer --since=11s
	// retry period is 10s, print  11s log to avoid the delay of go cmd package
	ec, err := cmdutil.RunCmdWithContext(ctx, opts.DryRun, "kubectl", "logs", "-n", "kubesphere-system", "deploy/ks-installer", "--since=11s")
	if err != nil {
		return err
	}
	if strings.Contains(ec.StdOut(), "Welcome to KubeSphere") {
		return nil
	}

	return fmt.Errorf("kubespere installation not completed")
}

func (i *CheckInstall) Uninstall(ctx context.Context, opts component.Options) ([]byte, error) {
	return nil, nil
}

func (i *CheckInstall) NewInstance() component.ObjectMeta {
	return &CheckInstall{}
}

type RegisterCluster struct {
	ClusterName   string
	ClusterType   string
	ServerAddress string
}

func (g *RegisterCluster) renderClusterConfig(ctx context.Context, data []byte, opts component.Options) error {
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		return err
	}
	ksClusterConf := filepath.Join(manifestDir, fmt.Sprintf("c-%s", g.ClusterName))
	return fileutil.WriteFileWithContext(ctx, ksClusterConf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644,
		func(w io.Writer) error {
			_, err := w.Write(data)
			return err
		}, opts.DryRun)
}

func (g *RegisterCluster) Install(ctx context.Context, opts component.Options) ([]byte, error) {
	cfgBytes := component.GetExtraData(ctx)
	if len(cfgBytes) == 0 {
		return nil, fmt.Errorf("unexpected error, member cluster kubeconfig not found")
	}
	cfg, err := clientcmd.Load(cfgBytes)
	if err != nil {
		return nil, err
	}
	cfg.Clusters[cfg.Contexts[cfg.CurrentContext].Cluster].Server = fmt.Sprintf("https://%s", g.ServerAddress)
	cfgBytes, err = clientcmd.Write(*cfg)
	if err != nil {
		return nil, err
	}
	kubeConfig := base64.StdEncoding.EncodeToString(cfgBytes)
	if err = g.renderClusterConfig(ctx, []byte(fmt.Sprintf(ksClusterFed, g.ClusterType, g.ClusterName, kubeConfig, g.ServerAddress)), opts); err != nil {
		return nil, err
	}
	_, err = cmdutil.RunCmdWithContext(ctx, opts.DryRun, "kubectl", "apply", "-f", filepath.Join(manifestDir, fmt.Sprintf("c-%s", g.ClusterName)))
	return nil, err
}

func (g *RegisterCluster) Uninstall(ctx context.Context, opts component.Options) ([]byte, error) {
	return nil, nil
}

func (g *RegisterCluster) NewInstance() component.ObjectMeta {
	return &RegisterCluster{}
}

type KsImagePullPolicy struct {
	plugin *PluginConfig
}

func (p *KsImagePullPolicy) ImageFiles() []string {
	images := []string{"images.tar.gz"}
	if p.plugin.EnableAppStore {
		images = append(images, "images-appstore.tar.gz")
	}
	if p.plugin.EnableServiceMesh {
		images = append(images, "images-servicemesh.tar.gz")
	}
	if p.plugin.EnableDevops {
		images = append(images, "images-devops.tar.gz")
	}
	return images
}
