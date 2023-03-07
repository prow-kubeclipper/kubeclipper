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

package app

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/kubeclipper/kubeclipper/cmd/kcctl/app/options"

	"github.com/kubeclipper/kubeclipper/pkg/cli/logger"
)

func NewKcMigrateCommand(in io.Reader, out, err io.Writer) *cobra.Command {
	cmds := &cobra.Command{
		Use:   "kc-migrate",
		Short: "kc-migrate: command line tool for migrate kubeclipper 4.3.0 to 4.3.1",
		Long: `How to use:
1.use kc-migrate backup to backup 4.3.0 data
2.use kc-migrate deploy to deploy 4.3.1
3.use kc-migrate restore to restore data
`,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	ioStreams := options.IOStreams{
		In:     in,
		Out:    out,
		ErrOut: err,
	}
	cmds.ResetFlags()
	cmds.CompletionOptions.DisableDefaultCmd = true
	logger.AddFlags(cmds.PersistentFlags())

	cmds.AddCommand(newCmdVersion(out))
	cmds.AddCommand(NewCmdDeploy(ioStreams))
	cmds.AddCommand(NewCmdBackup())
	cmds.AddCommand(NewCmdRestore())
	return cmds
}
