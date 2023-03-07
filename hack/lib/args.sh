#!/usr/bin/env bash

kube::args::arg_list() {
  kube::args::sign
  kube::args::pkg_url_prefix
}

kube::args::sign() {
  echo -X "'github.com/kubeclipper/kubeclipper/cmd/kcctl/app/options.Contact='"
}

kube::args::pkg_url_prefix() {
  echo -X "'github.com/kubeclipper/kubeclipper/pkg/cli/deploy.PkgURL='"
}
