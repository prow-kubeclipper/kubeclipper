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

package v1

import (
	"context"
	"fmt"
	"net/http"

	"github.com/kubeclipper/kubeclipper/pkg/license"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"

	"github.com/emicklei/go-restful"

	"github.com/kubeclipper/kubeclipper/pkg/server/restplus"
)

type LicenseRequest struct {
	License string `json:"license"`
}

func (h *handler) DescribeLicense(req *restful.Request, resp *restful.Response) {
	lic, err := h.platformOperator.GetPlatformSetting(req.Request.Context())
	if err != nil {
		restplus.HandleInternalError(resp, req, err)
		return
	}
	if lic.Name == "" {
		_ = resp.WriteHeaderAndEntity(http.StatusOK, license.LicenseInfo{})
		return
	}
	licInfo, err := h.licOperator.GetLicenseInfo(lic.License)
	if err != nil {
		restplus.HandleInternalError(resp, req, err)
		return
	}
	_ = resp.WriteHeaderAndEntity(http.StatusOK, licInfo)
}

func (h *handler) UpdateLicense(req *restful.Request, resp *restful.Response) {
	c := &LicenseRequest{}
	if err := req.ReadEntity(c); err != nil {
		restplus.HandleBadRequest(resp, req, err)
		return
	}
	valid, errDetail, err := h.licOperator.Verify(c.License)
	if err != nil || !valid {
		restplus.HandlerErrorWithCustomCode(resp, req, http.StatusBadRequest, http.StatusBadRequest, fmt.Sprintf("license not valid %s", errDetail), err)
		return
	}

	lic, err := h.platformOperator.GetPlatformSetting(req.Request.Context())
	if err != nil {
		restplus.HandleInternalError(resp, req, err)
		return
	}
	if lic.Name == "" {
		err := h.createPlatformSetting(req.Request.Context(), c.License)
		if err != nil {
			restplus.HandleInternalError(resp, req, err)
			return
		}
	} else {
		lic.License = c.License
		if _, err := h.platformOperator.UpdatePlatformSetting(req.Request.Context(), lic); err != nil {
			restplus.HandleInternalError(resp, req, err)
			return
		}
	}
	resp.WriteHeader(http.StatusOK)
}

func (h *handler) createPlatformSetting(ctx context.Context, lic string) error {
	p := &v1.PlatformSetting{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PlatformSetting",
			APIVersion: "core.kubeclipper.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "system-",
		},
		License: lic,
	}
	_, err := h.platformOperator.CreatePlatformSetting(ctx, p)
	return err
}
