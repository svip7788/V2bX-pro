package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/InazumaV/V2bX/node"
	log "github.com/sirupsen/logrus"
)

const (
	childRestartDelay = 3 * time.Second
	childStopTimeout  = 10 * time.Second
)

type workerGeneration struct {
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	children map[int]*exec.Cmd
	wg       sync.WaitGroup
}

type nodeGroup struct {
	ID    int
	Nodes []conf.NodeConfig
}

func newWorkerGeneration() *workerGeneration {
	ctx, cancel := context.WithCancel(context.Background())
	return &workerGeneration{
		ctx:      ctx,
		cancel:   cancel,
		children: make(map[int]*exec.Cmd),
	}
}

func (g *workerGeneration) setChild(nodeID int, cmd *exec.Cmd) {
	g.mu.Lock()
	g.children[nodeID] = cmd
	g.mu.Unlock()
}

func (g *workerGeneration) removeChild(nodeID int, cmd *exec.Cmd) {
	g.mu.Lock()
	if current, ok := g.children[nodeID]; ok && current == cmd {
		delete(g.children, nodeID)
	}
	g.mu.Unlock()
}

func (g *workerGeneration) snapshotChildren() map[int]*exec.Cmd {
	g.mu.Lock()
	defer g.mu.Unlock()
	snapshot := make(map[int]*exec.Cmd, len(g.children))
	for nodeID, cmd := range g.children {
		snapshot[nodeID] = cmd
	}
	return snapshot
}

type nodeProcessManager struct {
	configPath string

	mu      sync.Mutex
	current *workerGeneration
}

func newNodeProcessManager(configPath string) *nodeProcessManager {
	return &nodeProcessManager{configPath: configPath}
}

func (m *nodeProcessManager) StartAll(c *conf.Conf) error {
	groups, err := collectNodeGroups(c.NodeConfig)
	if err != nil {
		return err
	}
	gen := newWorkerGeneration()
	for _, group := range groups {
		gen.wg.Add(1)
		go m.runChildLoop(gen, group)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		gen.cancel()
		gen.wg.Wait()
		return errors.New("worker processes already running")
	}
	m.current = gen
	return nil
}

func (m *nodeProcessManager) Replace(c *conf.Conf) error {
	if _, err := collectNodeGroups(c.NodeConfig); err != nil {
		return err
	}
	if err := m.StopAll(); err != nil {
		return err
	}
	runtime.GC()
	return m.StartAll(c)
}

func (m *nodeProcessManager) StopAll() error {
	m.mu.Lock()
	gen := m.current
	m.current = nil
	m.mu.Unlock()
	if gen == nil {
		return nil
	}

	gen.cancel()
	sendSignalToChildren(gen.snapshotChildren(), syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		gen.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(childStopTimeout):
		log.Warn("Worker processes did not exit in time, forcing shutdown")
		sendSignalToChildren(gen.snapshotChildren(), os.Kill)
		<-done
		return nil
	}
}

func (m *nodeProcessManager) runChildLoop(gen *workerGeneration, group nodeGroup) {
	defer gen.wg.Done()

	for {
		select {
		case <-gen.ctx.Done():
			return
		default:
		}

		cmd, err := m.buildChildCommand(group)
		if err != nil {
			log.WithFields(log.Fields{
				"group_id": group.ID,
				"node_ids": formatNodeIDs(group.Nodes),
				"err":      err,
			}).Error("Build child process failed")
			if !waitForRestart(gen.ctx) {
				return
			}
			continue
		}

		if err := cmd.Start(); err != nil {
			log.WithFields(log.Fields{
				"group_id": group.ID,
				"node_ids": formatNodeIDs(group.Nodes),
				"err":      err,
			}).Error("Start child process failed")
			if !waitForRestart(gen.ctx) {
				return
			}
			continue
		}

		gen.setChild(group.ID, cmd)
		log.WithFields(log.Fields{
			"group_id": group.ID,
			"node_ids": formatNodeIDs(group.Nodes),
			"pid":      cmd.Process.Pid,
		}).Info("Node worker started")

		err = cmd.Wait()
		gen.removeChild(group.ID, cmd)
		if gen.ctx.Err() != nil {
			return
		}

		fields := log.Fields{
			"group_id": group.ID,
			"node_ids": formatNodeIDs(group.Nodes),
		}
		if cmd.Process != nil {
			fields["pid"] = cmd.Process.Pid
		}
		if err != nil {
			fields["err"] = err
			log.WithFields(fields).Warn("Node worker exited unexpectedly, restarting")
		} else {
			log.WithFields(fields).Warn("Node worker exited, restarting")
		}

		if !waitForRestart(gen.ctx) {
			return
		}
	}
}

func (m *nodeProcessManager) buildChildCommand(group nodeGroup) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable error: %w", err)
	}
	workDir := childWorkDir(executable, group.ID)
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, fmt.Errorf("create child work dir error: %w", err)
	}
	args := []string{
		"server",
		"-c", m.configPath,
		"--watch=false",
		"--child-node-group", strconv.Itoa(group.ID),
	}
	cmd := exec.Command(executable, args...)
	cmd.Dir = workDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd, nil
}

func configureServerLogging(c *conf.Conf) (func(), error) {
	switch strings.ToLower(c.LogConfig.Level) {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	if c.LogConfig.Output == "" {
		return func() {}, nil
	}
	f, err := os.OpenFile(c.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return func() {}, err
	}
	log.SetOutput(f)
	return func() {
		_ = f.Close()
	}, nil
}

func runMasterServer(c *conf.Conf, configPath string, enableWatch bool) error {
	groups, err := collectNodeGroups(c.NodeConfig)
	if err != nil {
		return err
	}
	if len(groups) > 1 && c.LogConfig.PprofListen != "" {
		log.WithField("listen", c.LogConfig.PprofListen).Warn("Pprof is disabled in master-worker mode with multiple nodes")
	}

	manager := newNodeProcessManager(configPath)
	if err := manager.StartAll(c); err != nil {
		return err
	}
	defer func() {
		if err := manager.StopAll(); err != nil {
			log.WithField("err", err).Error("Stop worker processes failed")
		}
	}()

	log.WithField("node_ids", formatNodeIDs(c.NodeConfig)).Info("V2bX master started")

	if enableWatch {
		watchPaths := detectWatchPaths(c)
		if err := c.Watch(configPath, func() {
			if err := manager.Replace(c); err != nil {
				log.WithField("err", err).Error("Reload worker processes failed")
				return
			}
			log.WithField("node_ids", formatNodeIDs(c.NodeConfig)).Info("Worker processes reloaded")
			runtime.GC()
		}, watchPaths...); err != nil {
			return err
		}
	}

	waitForShutdownSignal()
	return nil
}

func runChildGroupServer(c *conf.Conf, configPath string, groupID int) error {
	groups, err := collectNodeGroups(c.NodeConfig)
	if err != nil {
		return err
	}
	fullGroupCount := len(groups)
	selectedGroup, err := findNodeGroupByID(groups, groupID)
	if err != nil {
		return err
	}
	c.NodeConfig = selectedGroup.Nodes
	c.CoresConfig = filterCoreConfigsForNode(c.CoresConfig, selectedGroup.Nodes[0])

	if fullGroupCount > 1 && c.LogConfig.PprofListen != "" {
		// Each worker is a separate process, so give every group its own
		// pprof port (base+groupID) instead of disabling it outright.
		if listen, err := offsetListenPort(c.LogConfig.PprofListen, groupID); err != nil {
			log.WithFields(log.Fields{
				"group_id": groupID,
				"listen":   c.LogConfig.PprofListen,
				"err":      err,
			}).Warn("Invalid pprof listen, disable pprof in child mode")
			c.LogConfig.PprofListen = ""
		} else {
			c.LogConfig.PprofListen = listen
		}
	}

	log.WithFields(log.Fields{
		"group_id": groupID,
		"node_ids": formatNodeIDs(selectedGroup.Nodes),
	}).Info("Node worker booting")
	return runManagedNodeServer(c, configPath, false)
}

func runManagedNodeServer(c *conf.Conf, configPath string, enableWatch bool) error {
	if len(c.NodeConfig) == 0 {
		return errors.New("no node config")
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
	log.WithField("node_ids", formatNodeIDs(c.NodeConfig)).Info("Start V2bX worker runtime")

	vc, err := vCore.NewCore(c.CoresConfig)
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

	nodes := node.New()
	defer nodes.Close()

	if err := nodes.Start(c.NodeConfig, vc); err != nil {
		return fmt.Errorf("run nodes failed: %w", err)
	}
	log.Info("Nodes started")

	if enableWatch {
		watchPaths := detectWatchPaths(c)
		if err := c.Watch(configPath, func() {
			nodes.Close()
			if err := vc.Close(); err != nil {
				log.WithField("err", err).Error("Restart node failed")
				return
			}
			vc, err = vCore.NewCore(c.CoresConfig)
			if err != nil {
				log.WithField("err", err).Error("New core failed")
				return
			}
			if err := vc.Start(); err != nil {
				log.WithField("err", err).Error("Start core failed")
				return
			}
			log.Info("Core ", vc.Type(), " restarted")
			if err := nodes.Start(c.NodeConfig, vc); err != nil {
				log.WithField("err", err).Error("Run nodes failed")
				return
			}
			log.Info("Nodes restarted")
			runtime.GC()
		}, watchPaths...); err != nil {
			return err
		}
	}

	runtime.GC()
	waitForShutdownSignal()
	return nil
}

func detectWatchPaths(c *conf.Conf) []string {
	paths := make([]string, 0, 4)
	seen := make(map[string]struct{})
	appendPath := func(path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	for _, coreConfig := range c.CoresConfig {
		if coreConfig.XrayConfig == nil {
			continue
		}
		if path, _ := coreConfig.XrayConfig.ResolveDNSConfigPath(); path != "" {
			appendPath(path)
		}
		if path, _ := coreConfig.XrayConfig.ResolveInboundConfigPath(); path != "" {
			appendPath(path)
		}
		if path, _ := coreConfig.XrayConfig.ResolveRouteConfigPath(); path != "" {
			appendPath(path)
		}
		if path, _ := coreConfig.XrayConfig.ResolveOutboundConfigPath(); path != "" {
			appendPath(path)
		}
	}
	return paths
}

func collectNodeGroups(nodes []conf.NodeConfig) ([]nodeGroup, error) {
	if len(nodes) == 0 {
		return nil, errors.New("no node config")
	}
	groups := make([]nodeGroup, 0, len(nodes))
	seen := make(map[string]struct{})
	for i, nodeConfig := range nodes {
		expanded, err := nodeConfig.ExpandedNodes()
		if err != nil {
			return nil, err
		}
		for _, expandedNode := range expanded {
			key := fmt.Sprintf("%s|%s|%s|%d",
				strings.ToLower(expandedNode.ApiConfig.APIHost),
				expandedNode.ApiConfig.Key,
				strings.ToLower(expandedNode.ApiConfig.NodeType),
				expandedNode.ApiConfig.NodeID,
			)
			if _, ok := seen[key]; ok {
				return nil, fmt.Errorf("duplicate node target: %s %s %d",
					expandedNode.ApiConfig.APIHost,
					expandedNode.ApiConfig.NodeType,
					expandedNode.ApiConfig.NodeID,
				)
			}
			seen[key] = struct{}{}
		}
		groups = append(groups, nodeGroup{
			ID:    i + 1,
			Nodes: expanded,
		})
	}
	return groups, nil
}

func findNodeGroupByID(groups []nodeGroup, groupID int) (nodeGroup, error) {
	for _, group := range groups {
		if group.ID == groupID {
			return group, nil
		}
	}
	return nodeGroup{}, fmt.Errorf("node group %d not found in config", groupID)
}

func filterCoreConfigsForNode(coreConfigs []conf.CoreConfig, nodeConfig conf.NodeConfig) []conf.CoreConfig {
	if len(coreConfigs) <= 1 {
		return coreConfigs
	}

	if nodeConfig.Options.CoreName != "" {
		filtered := make([]conf.CoreConfig, 0, 1)
		for _, coreConfig := range coreConfigs {
			if coreConfig.Name == nodeConfig.Options.CoreName {
				filtered = append(filtered, coreConfig)
			}
		}
		if len(filtered) > 0 {
			return filtered
		}
	}

	if nodeConfig.Options.Core != "" {
		filtered := make([]conf.CoreConfig, 0, len(coreConfigs))
		for _, coreConfig := range coreConfigs {
			if strings.EqualFold(coreConfig.Type, nodeConfig.Options.Core) {
				filtered = append(filtered, coreConfig)
			}
		}
		if len(filtered) > 0 {
			return filtered
		}
	}

	return coreConfigs
}

func formatNodeIDs(nodes []conf.NodeConfig) string {
	if len(nodes) == 0 {
		return ""
	}
	ids := make([]string, 0, len(nodes))
	for _, nodeConfig := range nodes {
		for _, nodeID := range nodeConfig.ApiConfig.GetNodeIDs() {
			ids = append(ids, strconv.Itoa(nodeID))
		}
	}
	return strings.Join(ids, ",")
}

func childWorkDir(executable string, groupID int) string {
	return filepath.Join(filepath.Dir(executable), fmt.Sprintf("group-%d", groupID))
}

func sendSignalToChildren(children map[int]*exec.Cmd, sig os.Signal) {
	for groupID, cmd := range children {
		if cmd == nil || cmd.Process == nil {
			continue
		}
		if err := cmd.Process.Signal(sig); err != nil && !errors.Is(err, os.ErrProcessDone) {
			log.WithFields(log.Fields{
				"group_id": groupID,
				"pid":      cmd.Process.Pid,
				"err":      err,
			}).Warn("Signal child process failed")
		}
	}
}

// offsetListenPort returns the listen address with its port shifted by delta,
// used to give each worker process a distinct pprof port.
func offsetListenPort(listen string, delta int) (string, error) {
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	newPort := port + delta
	if newPort < 1 || newPort > 65535 {
		return "", fmt.Errorf("port out of range: %d", newPort)
	}
	return net.JoinHostPort(host, strconv.Itoa(newPort)), nil
}

func waitForRestart(ctx context.Context) bool {
	timer := time.NewTimer(childRestartDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func waitForShutdownSignal() {
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(osSignals)
	<-osSignals
}
