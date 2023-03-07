package rancher

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kubeclipper/kubeclipper/pkg/component"
	"github.com/kubeclipper/kubeclipper/pkg/component/utils"
	"github.com/kubeclipper/kubeclipper/pkg/utils/cmdutil"
)

const (
	Name              = "rancher"
	Version           = "v3"
	AgentCheckInstall = "CheckInstall"
)

var (
	_ component.StepRunnable = (*CheckInstall)(nil)
)

func init() {
	if err := component.RegisterAgentStep(fmt.Sprintf(component.RegisterStepKeyFormat, Name, Version, AgentCheckInstall), &CheckInstall{}); err != nil {
		panic(err)
	}
}

type CheckInstall struct {
}

func (i *CheckInstall) Install(ctx context.Context, opts component.Options) ([]byte, error) {
	if err := utils.RetryFunc(ctx, opts, 10*time.Second, "checkAgentInstall", i.checkAgentInstall); err != nil {
		return nil, err
	}
	return nil, nil
}

func (i *CheckInstall) checkAgentInstall(ctx context.Context, opts component.Options) error {
	// docker logs optimistic_germain --since=11s
	// retry period is 10s, print  11s log to avoid the delay of go cmd package
	ec, err := cmdutil.RunCmdWithContext(ctx, opts.DryRun, "bash", "-c", `docker logs $(docker ps --no-trunc|grep "rancher-agent"|grep "worker"|awk '{print $1}') --since=11s`)
	if err != nil {
		return err
	}
	// rancher v2.3.6
	if strings.Contains(ec.StdOut(), "Starting plan monitor") && !strings.Contains(ec.StdOut(), "Starting plan monitor, checking every") {
		return nil
	}
	// rancher v2.6.0
	if strings.Contains(ec.StdOut(), "Plan monitor checking") {
		return nil
	}
	return fmt.Errorf("base image download not completed")
}

func (i *CheckInstall) Uninstall(ctx context.Context, opts component.Options) ([]byte, error) {
	return nil, nil
}

func (i *CheckInstall) NewInstance() component.ObjectMeta {
	return &CheckInstall{}
}
