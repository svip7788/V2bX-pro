package cmd

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/InazumaV/V2bX/machine"
	log "github.com/sirupsen/logrus"
)

// runMachineServer 机器模式单进程运行：节点由面板下发并可热增删，故不拆子进程；
// 多站时各面板一个 Manager，共用同一组内核
func runMachineServer(c *conf.Conf) error {
	machines := c.Machines()
	for _, mc := range machines {
		if strings.TrimSpace(mc.APIHost) == "" || mc.Token == "" {
			return fmt.Errorf("机器 #%d 的 ApiHost 和 Token 不能为空", mc.MachineID)
		}
	}
	if len(c.NodeConfig) > 0 {
		log.Warn("Machine mode enabled, Nodes in config are ignored")
	}

	if c.LogConfig.PprofListen != "" {
		go func() {
			log.Infof("pprof listening on %s", c.LogConfig.PprofListen)
			if err := http.ListenAndServe(c.LogConfig.PprofListen, nil); err != nil {
				log.WithField("err", err).Error("pprof server failed")
			}
		}()
	}

	limiter.Init()
	vc, err := vCore.NewCore(conf.MachineCoreConfigs(c.CoresConfig))
	if err != nil {
		return fmt.Errorf("new core failed: %w", err)
	}
	defer func() {
		if err := vc.Close(); err != nil {
			log.WithField("err", err).Error("Close core failed")
		}
	}()
	if err := vc.Start(); err != nil {
		return fmt.Errorf("start core failed: %w", err)
	}
	log.Info("Core ", vc.Type(), " started")

	managers := make([]*machine.Manager, 0, len(machines))
	defer func() {
		for _, m := range managers {
			m.Close()
		}
	}()
	for _, mc := range machines {
		m, err := machine.NewManager(mc, vc, version)
		if err != nil {
			return err
		}
		m.Start()
		managers = append(managers, m)
	}

	runtime.GC()
	waitForShutdownSignal()
	return nil
}
