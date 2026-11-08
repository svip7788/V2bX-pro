package cmd

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	config          string
	watch           bool
	childGroupIndex int
	pprofListen     string
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run V2bX server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/V2bX/config.json", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	serverCommand.PersistentFlags().
		StringVar(&pprofListen, "pprof-listen", "",
			"temporary pprof listen address")
	serverCommand.Flags().
		IntVar(&childGroupIndex, "child-node-group", 0, "internal child node group")
	_ = serverCommand.Flags().MarkHidden("child-node-group")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	panel.UserAgent = "V2bX/" + version
	watchPprofSignal()
	if childGroupIndex == 0 {
		showVersion()
		applyMemoryLimit()
	}
	c := conf.New()
	err := c.LoadFromPath(config)
	if err != nil {
		log.WithField("err", err).Error("Load config file failed")
		return
	}
	applyServerRuntimeOverrides(c)

	cleanup, err := configureServerLogging(c)
	if err != nil {
		log.WithField("err", err).Error("Open log file failed, using stdout instead")
	}
	defer cleanup()

	if len(c.Machines()) > 0 && childGroupIndex == 0 {
		if err := runMachineServer(c); err != nil {
			log.WithField("err", err).Error("Run machine server failed")
		}
		return
	}

	if childGroupIndex > 0 {
		if err := runChildGroupServer(c, config, childGroupIndex); err != nil {
			log.WithFields(log.Fields{
				"group_id": childGroupIndex,
				"err":      err,
			}).Error("Run child group failed")
		}
		return
	}

	if err := runMasterServer(c, config, watch); err != nil {
		log.WithField("err", err).Error("Run master server failed")
	}
}

// applyMemoryLimit 未显式设置 GOMEMLIMIT 时按物理内存 75% 设软上限：
// 平时不影响，连接数暴涨接近上限时 GC 提前回收，避免整机 OOM
func applyMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	var kb int64
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ = strconv.ParseInt(fields[1], 10, 64)
			}
			break
		}
	}
	if kb <= 0 {
		return
	}
	limit := kb * 1024 / 4 * 3
	debug.SetMemoryLimit(limit)
	log.Infof("Go memory limit set to %d MiB", limit>>20)
}

func applyServerRuntimeOverrides(c *conf.Conf) {
	if pprofListen != "" {
		c.LogConfig.PprofListen = pprofListen
	}
}
