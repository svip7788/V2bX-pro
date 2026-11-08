package machine

import (
	"archive/zip"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultRepo = "svip7788/V2bX-pro"

var (
	repoPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,64}$`)
	githubMirrors  = []string{
		"https://github.com/",
		"https://edgeone.gh-proxy.com/https://github.com/",
		"https://gh.idayer.com/https://github.com/",
		"https://ghfile.geekertao.top/https://github.com/",
		"https://gh-proxy.com/https://github.com/",
		"https://gh.llkk.cc/https://github.com/",
		"https://ghfast.top/https://github.com/",
		"https://ghproxy.net/https://github.com/",
	}
	relaxedMirrors = []string{
		"https://github.com/",
		"https://gh-proxy.com/https://github.com/",
	}
	sha256Pattern = regexp.MustCompile(`(?m)^SHA2-256=\s*([0-9a-f]{64})`)
	sha256Hex     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func releaseArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "64", nil
	case "arm64":
		return "arm64-v8a", nil
	case "s390x":
		return "s390x", nil
	}
	return "", fmt.Errorf("当前架构不支持自动升级: %s", runtime.GOARCH)
}

// upgrade 返回是否需要重启、结论（过程经 progress 上报）
func (r *commandRunner) upgrade(cmd command) (bool, string, error) {
	var p struct {
		Version string `json:"version"`
		Repo    string `json:"repo"`
		// 面板缓存的安装包目录（以 / 结尾）及各包 SHA256，节点到面板通常比到 GitHub 快得多
		Mirror string            `json:"mirror"`
		SHA256 map[string]string `json:"sha256"`
	}
	_ = json.Unmarshal(cmd.Params, &p)
	p.Version = strings.TrimSpace(p.Version)
	p.Repo = strings.TrimSpace(p.Repo)
	if p.Repo == "" {
		p.Repo = defaultRepo
	}
	logf := func(format string, args ...any) {
		r.progress(cmd.ID, fmt.Sprintf(">>> "+format, args...))
	}
	if !versionPattern.MatchString(p.Version) || p.Version == "latest" {
		return false, "", fmt.Errorf("版本号无效: %q", p.Version)
	}
	if !repoPattern.MatchString(p.Repo) {
		return false, "", fmt.Errorf("仓库格式无效: %q", p.Repo)
	}
	if cur := r.m.currentVersion(); cur == p.Version {
		return false, ">>> 当前已是 " + cur + "，无需升级", nil
	}
	arch, err := releaseArch()
	if err != nil {
		return false, "", err
	}

	stage, err := os.MkdirTemp("", "v2bx-upgrade-")
	if err != nil {
		return false, "", err
	}
	defer os.RemoveAll(stage)

	asset := fmt.Sprintf("V2bX-linux-%s.zip", arch)
	path := fmt.Sprintf("%s/releases/download/%s/%s", p.Repo, p.Version, asset)
	zipFile := filepath.Join(stage, "V2bX.zip")
	expected := strings.ToLower(p.SHA256[asset])
	if !sha256Hex.MatchString(expected) {
		expected = fetchSHA256(r.m.ctx, p.Repo, p.Version, asset)
	}
	if expected == "" {
		logf("未能从 GitHub 获取 SHA256，仅校验压缩包完整性（无法防止镜像篡改）")
	}
	downloaded := false
	try := func(url string, opt downloadOptions) bool {
		logf("下载: %s", url)
		opt.progress = func(done, total int64, speed float64) {
			if total > 0 {
				logf("已下载 %.1f/%.1f MB，%.0f KB/s", float64(done)/1e6, float64(total)/1e6, speed/1024)
			} else {
				logf("已下载 %.1f MB，%.0f KB/s", float64(done)/1e6, speed/1024)
			}
		}
		if err := download(r.m.ctx, url, zipFile, opt); err != nil {
			logf("失败: %v", err)
			return false
		}
		if err := verifyZip(zipFile, expected); err != nil {
			logf("校验失败: %v", err)
			return false
		}
		return true
	}
	if strings.HasPrefix(p.Mirror, "https://") || strings.HasPrefix(p.Mirror, "http://") {
		downloaded = try(p.Mirror+asset, downloadOptions{maxTime: 10 * time.Minute, minSpeed: 50 << 10})
	}
	if !downloaded {
		logf("测速 GitHub 下载源")
		for _, mirror := range rankMirrors(r.m.ctx, githubMirrors, path) {
			if downloaded = try(mirror+path, downloadOptions{maxTime: 10 * time.Minute, minSpeed: 100 << 10}); downloaded {
				break
			}
		}
	}
	if !downloaded {
		logf("所有下载源均较慢，放宽限速重试")
		for _, mirror := range relaxedMirrors {
			if downloaded = try(mirror+path, downloadOptions{maxTime: 30 * time.Minute, minSpeed: 20 << 10}); downloaded {
				break
			}
		}
	}
	if !downloaded {
		return false, "", fmt.Errorf("所有下载源均失败")
	}

	extractDir := filepath.Join(stage, "files")
	if err := unzip(zipFile, extractDir); err != nil {
		return false, "", fmt.Errorf("解压失败: %w", err)
	}
	newBin := filepath.Join(extractDir, "V2bX")
	if err := os.Chmod(newBin, 0755); err != nil {
		return false, "", fmt.Errorf("压缩包中未找到 V2bX: %w", err)
	}
	ctx, cancel := context.WithTimeout(r.m.ctx, 15*time.Second)
	verOut, err := exec.CommandContext(ctx, newBin, "version").CombinedOutput()
	cancel()
	if err != nil {
		return false, "", fmt.Errorf("新版本无法运行: %v %s", err, truncateTail(string(verOut)))
	}
	logf("新版本校验通过")

	dir := execDir()
	exe := filepath.Join(dir, "V2bX")
	if err := copyFile(exe, exe+".bak", 0755); err != nil {
		return false, "", fmt.Errorf("备份旧版本失败: %w", err)
	}
	if err := copyFile(newBin, exe+".new", 0755); err != nil {
		return false, "", fmt.Errorf("写入新版本失败: %w", err)
	}
	if err := os.Rename(exe+".new", exe); err != nil {
		_ = os.Remove(exe + ".new")
		return false, "", fmt.Errorf("替换二进制失败: %w", err)
	}
	logf("已替换 %s（旧版本备份为 V2bX.bak）", exe)

	for _, f := range []string{"geoip.dat", "geosite.dat"} {
		src := filepath.Join(extractDir, f)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		_ = copyFile(src, filepath.Join(dir, f), 0644)
		_ = copyFile(src, filepath.Join("/etc/V2bX", f), 0644)
	}
	_ = os.WriteFile(filepath.Join(dir, ".version"), []byte(p.Version+"\n"), 0644)
	_ = os.WriteFile(versionFile, []byte(p.Version+"\n"), 0644)
	r.refreshScript(p.Repo, p.Version, logf)
	return true, ">>> 升级到 " + p.Version + " 完成，V2bX 即将重启", nil
}

const scriptPath = "/usr/bin/V2bX"

// refreshScript 同步该版本的管理脚本，失败不影响升级
func (r *commandRunner) refreshScript(repo, version string, logf func(string, ...any)) {
	if _, err := os.Stat(scriptPath); err != nil {
		return
	}
	raw := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/install/V2bX.sh", repo, version)
	tmp := scriptPath + ".new"
	for _, url := range []string{raw, "https://ghfast.top/" + raw} {
		if download(r.m.ctx, url, tmp, downloadOptions{maxTime: time.Minute}) == nil && os.Chmod(tmp, 0755) == nil && os.Rename(tmp, scriptPath) == nil {
			logf("管理脚本已同步")
			return
		}
	}
	_ = os.Remove(tmp)
	logf("管理脚本同步失败，可稍后执行 V2bX update_shell")
}

type downloadOptions struct {
	maxTime time.Duration
	// 连续两个检测窗口平均速度低于该值（B/s）时放弃，0 表示不检测
	minSpeed int64
	progress func(done, total int64, speed float64)
}

type countingWriter struct {
	w io.Writer
	n atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

const downloadCheckInterval = 15 * time.Second

func download(ctx context.Context, url, dest string, opt downloadOptions) error {
	ctx, cancel := context.WithTimeout(ctx, opt.maxTime)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	cw := &countingWriter{w: f}
	var slow atomic.Bool
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(downloadCheckInterval)
		defer ticker.Stop()
		var last int64
		var slowWindows int
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				cur := cw.n.Load()
				speed := float64(cur-last) / downloadCheckInterval.Seconds()
				last = cur
				if opt.progress != nil {
					opt.progress(cur, resp.ContentLength, speed)
				}
				if opt.minSpeed <= 0 || speed >= float64(opt.minSpeed) {
					slowWindows = 0
				} else if slowWindows++; slowWindows >= 2 {
					slow.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	n, err := io.Copy(cw, resp.Body)
	close(done)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil && slow.Load() {
		err = fmt.Errorf("速度低于 %d KB/s", opt.minSpeed>>10)
	} else if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("超过 %s 未下载完成", opt.maxTime)
	}
	if err == nil && n == 0 {
		err = fmt.Errorf("文件为空")
	}
	return err
}

const (
	probeBytes   = 1 << 20
	probeTimeout = 8 * time.Second
)

// rankMirrors 并发拉取各源开头一段测速，按速度从快到慢排序；测速失败的排在最后、保持原顺序
func rankMirrors(ctx context.Context, mirrors []string, path string) []string {
	speeds := make([]float64, len(mirrors))
	var wg sync.WaitGroup
	for i, m := range mirrors {
		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()
			speeds[i] = probeSpeed(ctx, url)
		}(i, m+path)
	}
	wg.Wait()
	ranked := slices.Clone(mirrors)
	idx := make(map[string]int, len(mirrors))
	for i, m := range mirrors {
		idx[m] = i
	}
	slices.SortStableFunc(ranked, func(a, b string) int {
		return cmp.Compare(speeds[idx[b]], speeds[idx[a]])
	})
	return ranked
}

// probeSpeed 返回 B/s，失败返回 0
func probeSpeed(ctx context.Context, url string) float64 {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", probeBytes-1))
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0
	}
	// 超时前读到的部分也计入，慢源不至于全部记为 0
	n, _ := io.CopyN(io.Discard, resp.Body, probeBytes)
	if n < 64<<10 {
		return 0
	}
	return float64(n) / time.Since(start).Seconds()
}

// fetchSHA256 只从 GitHub 获取校验值：镜像可同时篡改压缩包和 .dgst，其返回的校验值不可信。失败返回空串
func fetchSHA256(ctx context.Context, repo, version, asset string) string {
	tmp, err := os.CreateTemp("", "v2bx-dgst-")
	if err != nil {
		return ""
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	opt := downloadOptions{maxTime: 20 * time.Second}

	dgst := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s.dgst", repo, version, asset)
	if download(ctx, dgst, tmp.Name(), opt) == nil {
		raw, _ := os.ReadFile(tmp.Name())
		if m := sha256Pattern.FindSubmatch(raw); m != nil {
			return string(m[1])
		}
	}

	api := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repo, version)
	if download(ctx, api, tmp.Name(), opt) == nil {
		raw, _ := os.ReadFile(tmp.Name())
		var release struct {
			Assets []struct {
				Name   string `json:"name"`
				Digest string `json:"digest"`
			} `json:"assets"`
		}
		if json.Unmarshal(raw, &release) == nil {
			for _, a := range release.Assets {
				if d := strings.TrimPrefix(a.Digest, "sha256:"); a.Name == asset && sha256Hex.MatchString(d) {
					return d
				}
			}
		}
	}
	return ""
}

// verifyZip 镜像可能返回网页或被篡改
func verifyZip(file, expected string) error {
	zr, err := zip.OpenReader(file)
	if err != nil {
		return fmt.Errorf("不是有效的压缩包: %w", err)
	}
	zr.Close()
	if expected == "" {
		return nil
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expected {
		return fmt.Errorf("SHA256 不一致")
	}
	return nil
}

func unzip(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	root := filepath.Clean(dest) + string(os.PathSeparator)
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(target, root) {
			return fmt.Errorf("非法路径: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := extractFile(f, target); err != nil {
			return err
		}
	}
	return nil
}

func extractFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	w, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, rc); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, perm)
}
