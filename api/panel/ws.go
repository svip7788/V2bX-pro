package panel

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"encoding/json"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// 面板每 25~55s 发一次 ping；超过 wsReadTimeout 没有任何消息视为半开连接，主动断开重连
const (
	wsReadTimeout  = 90 * time.Second
	wsWriteTimeout = 10 * time.Second
)

type WSEvent struct {
	Event     string          `json:"event"`
	Data      json.RawMessage `json:"data"`
	Timestamp int64           `json:"timestamp,omitempty"`
}

type WSConfigData struct {
	Config json.RawMessage `json:"config"`
}

type WSUsersData struct {
	Users []UserInfo `json:"users"`
}

type WSUserDeltaData struct {
	Action string     `json:"action"`
	Users  []UserInfo `json:"users"`
}

// WSSpeedLimitData 面板汇总判定后下发的动态限速
type WSSpeedLimitData struct {
	Users []struct {
		ID         int `json:"id"`
		LimitSpeed int `json:"limit_speed"` // Mbps
		LimitTime  int `json:"limit_time"`  // 秒
	} `json:"users"`
}

// WSSpeedShareData 用户同时在多个节点活跃时，面板下发固定限速的平分份数
type WSSpeedShareData struct {
	Users []struct {
		ID      int `json:"id"`
		Divisor int `json:"divisor"` // 1 表示恢复完整限速
		TTL     int `json:"ttl"`     // 秒
	} `json:"users"`
}

type WSDevicesData struct {
	Users map[string][]string `json:"users"`
}

type WSClient struct {
	conn     *websocket.Conn
	mu       sync.Mutex
	closed   bool
	stopCh   chan struct{}
	eventCh  chan WSEvent
	dropped  atomic.Bool
	apiHost  string
	token    string
	nodeId   int
	nodeType string
	// >0 时为机器级连接：整台机器一条连接，事件 data 内带 node_id
	machineID int
	// 返回 true 表示已处理，不进事件队列（终端按键等高频事件，避免占满队列触发全量同步）
	direct atomic.Pointer[func(WSEvent) bool]
}

func (ws *WSClient) SetDirectHandler(fn func(WSEvent) bool) {
	ws.direct.Store(&fn)
}

func (ws *WSClient) queueEvent(evt WSEvent) {
	select {
	case ws.eventCh <- evt:
	default:
		ws.dropped.Store(true)
		log.Warn("WS event channel full, dropping event: ", evt.Event)
	}
}

type HandshakeResponse struct {
	Websocket struct {
		Enabled bool   `json:"enabled"`
		WsURL   string `json:"ws_url"`
	} `json:"websocket"`
}

func (c *Client) Handshake() (*HandshakeResponse, error) {
	const path = "/api/v2/server/handshake"
	r, err := c.client.R().
		ForceContentType("application/json").
		Post(path)
	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}
	var resp HandshakeResponse
	if err := json.Unmarshal(r.Body(), &resp); err != nil {
		return nil, fmt.Errorf("unmarshal handshake response error: %w", err)
	}
	return &resp, nil
}

func (c *Client) NewWSClient(wsURL string) (*WSClient, error) {
	return startWSClient(wsURL, &WSClient{
		stopCh:   make(chan struct{}),
		eventCh:  make(chan WSEvent, 256),
		apiHost:  c.APIHost,
		token:    c.Token,
		nodeId:   c.NodeId,
		nodeType: c.NodeType,
	})
}

func startWSClient(wsURL string, ws *WSClient) (*WSClient, error) {
	if err := ws.connect(wsURL); err != nil {
		return nil, err
	}
	go ws.readLoop()
	go ws.reconnectLoop(wsURL)
	return ws, nil
}

func (ws *WSClient) connect(wsURL string) error {
	u, err := url.Parse(wsURL)
	if err != nil {
		return fmt.Errorf("parse ws url error: %w", err)
	}
	q := u.Query()
	q.Set("token", ws.token)
	if ws.machineID > 0 {
		q.Set("machine_id", strconv.Itoa(ws.machineID))
		// multi: 面板可把内容相同的节点事件合并成一条，data 内带 node_ids
		q.Set("caps", "multi")
	} else {
		q.Set("node_id", strconv.Itoa(ws.nodeId))
	}
	u.RawQuery = q.Encode()

	if !strings.HasPrefix(u.Scheme, "ws") {
		if strings.HasPrefix(u.Scheme, "https") {
			u.Scheme = "wss"
		} else {
			u.Scheme = "ws"
		}
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	conn, _, err := dialer.Dial(u.String(), http.Header{"User-Agent": {UserAgent}})
	if err != nil {
		return fmt.Errorf("ws dial error: %w", err)
	}
	ws.mu.Lock()
	if ws.closed {
		ws.mu.Unlock()
		conn.Close()
		return fmt.Errorf("ws client already closed")
	}
	ws.conn = conn
	ws.mu.Unlock()
	return nil
}

func (ws *WSClient) readLoop() {
	for {
		select {
		case <-ws.stopCh:
			return
		default:
		}
		ws.mu.Lock()
		conn := ws.conn
		ws.mu.Unlock()
		if conn == nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(wsReadTimeout))
		_, message, err := conn.ReadMessage()
		if err != nil {
			if ws.isClosed() {
				return
			}
			log.WithField("err", err).Warn("WS read error, will reconnect")
			ws.mu.Lock()
			conn.Close()
			ws.conn = nil
			ws.mu.Unlock()
			continue
		}

		var evt WSEvent
		if err := json.Unmarshal(message, &evt); err != nil {
			log.WithField("err", err).Warn("WS unmarshal event error")
			continue
		}

		if evt.Event == "ping" {
			ws.send([]byte(`{"event":"pong"}`))
			continue
		}

		if evt.Event == "auth.success" {
			log.Info("WS auth success")
			continue
		}

		if evt.Event == "error" {
			log.WithField("data", string(evt.Data)).Error("WS received error event")
			continue
		}

		if fn := ws.direct.Load(); fn != nil && (*fn)(evt) {
			continue
		}

		ws.queueEvent(evt)
	}
}

func (ws *WSClient) reconnectLoop(wsURL string) {
	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		// 面板重启时所有机器同时掉线，加随机抖动错开重连
		wait := backoff + time.Duration(rand.Int63n(int64(backoff)))
		select {
		case <-ws.stopCh:
			return
		case <-time.After(wait):
		}
		ws.mu.Lock()
		conn := ws.conn
		ws.mu.Unlock()
		if conn != nil {
			backoff = 2 * time.Second
			continue
		}
		if ws.isClosed() {
			return
		}
		log.Info("WS attempting reconnect...")
		if err := ws.connect(wsURL); err != nil {
			log.WithField("err", err).Warn("WS reconnect failed")
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			log.Info("WS reconnected")
			ws.queueEvent(WSEvent{Event: "sync.config"})
			backoff = 2 * time.Second
		}
	}
}

func (ws *WSClient) send(data []byte) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.conn == nil {
		return
	}
	_ = ws.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	_ = ws.conn.WriteMessage(websocket.TextMessage, data)
}

func (ws *WSClient) Events() <-chan WSEvent {
	return ws.eventCh
}

func (ws *WSClient) SendDeviceReport(data map[int][]string) {
	msg, err := json.Marshal(map[string]interface{}{
		"event": "report.devices",
		"data":  data,
	})
	if err != nil {
		log.WithField("err", err).Warn("WS marshal device report failed")
		return
	}
	ws.send(msg)
}

// Send 发送任意事件，连接断开时静默丢弃
func (ws *WSClient) Send(event string, data any) {
	msg, err := json.Marshal(map[string]any{
		"event": event,
		"data":  data,
	})
	if err != nil {
		log.WithField("err", err).Warn("WS marshal message failed")
		return
	}
	ws.send(msg)
}

// SendNodeDeviceReport 机器级连接上报单个节点的在线设备
func (ws *WSClient) SendNodeDeviceReport(nodeID int, data map[int][]string) {
	ws.Send("report.devices", map[string]any{
		"node_id": nodeID,
		"devices": data,
	})
}

func (ws *WSClient) DroppedAndReset() bool {
	return ws.dropped.Swap(false)
}

func (ws *WSClient) IsConnected() bool {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.conn != nil && !ws.closed
}

func (ws *WSClient) isClosed() bool {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.closed
}

func (ws *WSClient) Close() {
	ws.mu.Lock()
	if ws.closed {
		ws.mu.Unlock()
		return
	}
	ws.closed = true
	close(ws.stopCh)
	if ws.conn != nil {
		ws.conn.Close()
	}
	ws.mu.Unlock()
}
