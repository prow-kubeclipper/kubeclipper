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
	"os"
	"testing"
)

func TestKubesphere_renderInstaller(t *testing.T) {
	ks := &Kubesphere{
		ImageRepoMirror: "",
		JwtSecret:       "test",
		Version:         "v3.2.1",
		ClusterRole:     "host",
		ClusterType:     "",
		HostClusterName: "",
		StorageClass:    "nfs",
		Console: &ConsoleConfig{
			EnableMultiLogin: true,
			Port:             30000,
		},
		Monitor: &MonitorConfig{
			PrometheusReplicas:    1,
			PrometheusMemoryLimit: "500Mi",
			PrometheusVolumeSize:  "20Gi",
			PrometheusCPULimit:    "4",
			AlertManagerReplicas:  1,
		},
		Es: &ElasticSearchConfig{
			ElasticsearchMasterReplicas:   1,
			ElasticsearchDataReplicas:     1,
			ElasticsearchMasterVolumeSize: "20Gi",
			ElasticsearchDataVolumeSize:   "50Gi",
			LogMaxAge:                     7,
			ElkPrefix:                     "logstash",
		},
		Plugin: &PluginConfig{
			EnableEvent:        true,
			EnableDevops:       true,
			EnableLogging:      true,
			EnableAlert:        true,
			EnableNetwork:      true,
			EnableAudit:        true,
			EnableMetricServer: true,
			EnableServiceMesh:  true,
		},
	}
	//_ = ks.renderInstaller(os.Stdout)
	if err := ks.renderClusterConf(os.Stdout); err != nil {
		t.Error(err)
	}
}
