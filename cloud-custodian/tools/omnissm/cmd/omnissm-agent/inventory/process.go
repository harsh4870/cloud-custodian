// Copyright 2018 Capital One Services, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inventory

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/aws/amazon-ssm-agent/agent/appconfig"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ssm"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/sysmon"
)

var ProcessCmd = &cobra.Command{
	Use:   "ps",
	Short: "",
	Run: func(cmd *cobra.Command, args []string) {
		info, err := ssm.GetInstanceInformation()
		if err != nil {
			log.Fatal().Err(err).Msg("cannot get instance information")
		}
		logger := log.With().Str("ManagedId", info.InstanceId).Logger()
		processes, err := sysmon.ListAllProcesses()
		if err != nil {
			log.Fatal().Err(err).Msg("cannot list processes")
		}
		inventory := map[string]interface{}{
			"SchemaVersion": "1.0",
			"TypeName":      "Custom:ProcessInfo",
			"CaptureTime":   time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"Content":       processes,
		}
		data, err := json.MarshalIndent(inventory, "", "   ")
		if err != nil {
			logger.Fatal().Err(err).Msg("cannot marshal inventory")
		}
		path := filepath.Join(appconfig.DefaultDataStorePath, info.InstanceId, "inventory/custom/ProcessInfo.json")
		if err := ioutil.WriteFile(path, data, 0644); err != nil {
			logger.Fatal().Err(err).Msgf("cannot write file: %#v", path)
		}
		logger.Info().Msg("process inventory completed successfully")
	},
}
