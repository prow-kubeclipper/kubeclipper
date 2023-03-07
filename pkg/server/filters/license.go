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

package filters

import (
	"net/http"
	"strings"

	"github.com/kubeclipper/kubeclipper/pkg/client/clientrest"

	"github.com/kubeclipper/kubeclipper/pkg/models/platform"
	"github.com/kubeclipper/kubeclipper/pkg/server/restplus"

	"github.com/emicklei/go-restful"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/kubeclipper/kubeclipper/pkg/license"
	"github.com/kubeclipper/kubeclipper/pkg/logger"
)

const (
	ErrLicenseInvalid = 10000
)

func WithLicense(operator platform.Operator, licOperator license.Interface, excludePaths []string) restful.FilterFunction {
	if licOperator == nil {
		logger.Warn("License is disabled")
		return nil
	}
	var prefixes []string
	paths := sets.NewString()
	for _, p := range excludePaths {
		p = strings.TrimPrefix(p, "/")
		if len(p) == 0 {
			// matches "/"
			paths.Insert(p)
			continue
		}
		if strings.ContainsRune(p[:len(p)-1], '*') {
			logger.Warnf("only trailing * allowed in %q", p)
			continue
		}
		if strings.HasSuffix(p, "*") {
			prefixes = append(prefixes, p[:len(p)-1])
		} else {
			paths.Insert(p)
		}
	}
	a := PathExclude{
		excludePaths: paths,
		prefixes:     prefixes,
	}
	return func(req *restful.Request, response *restful.Response, chain *restful.FilterChain) {
		if clientrest.IsInformerRawQuery(req.Request) {
			chain.ProcessFilter(req, response)
			return
		}
		pth := strings.TrimPrefix(req.Request.URL.Path, "/")
		if a.excludePaths.Has(pth) || a.hasPrefix(pth) {
			chain.ProcessFilter(req, response)
			return
		}
		lic, err := operator.GetPlatformSetting(req.Request.Context())
		if err != nil {
			restplus.HandleInternalError(response, req, err)
			return
		}
		if lic.Name == "" || lic.License == "" {
			restplus.HandlerErrorWithCustomCode(response, req, http.StatusUnauthorized, ErrLicenseInvalid, "license invalid", nil)
			return
		}
		valid, errDetail, err := licOperator.Verify(lic.License)
		if err != nil {
			restplus.HandleInternalError(response, req, err)
			return
		}
		if !valid {
			restplus.HandlerErrorWithCustomCode(response, req, http.StatusUnauthorized, ErrLicenseInvalid, errDetail, nil)
			return
		}
		chain.ProcessFilter(req, response)
	}
}
