package conf

type LimitConfig struct {
	SpeedLimit              int                      `json:"SpeedLimit"`
	EnableDynamicSpeedLimit bool                     `json:"EnableDynamicSpeedLimit"`
	DynamicSpeedLimitConfig *DynamicSpeedLimitConfig `json:"DynamicSpeedLimitConfig"`
	BTBanMinutes            int                      `json:"BTBanMinutes"` // ban user on this node after BitTorrent is detected, default 2
}

type DynamicSpeedLimitConfig struct {
	DyLimitDuration     string `json:"DyLimitDuration"`     // time periods, e.g. "20:00-24:00,00:00-02:00", empty = all day, UTC+8
	DyLimitTriggerTime  int    `json:"DyLimitTriggerTime"`  // trigger window in seconds, default 60
	DyLimitTriggerSpeed int    `json:"DyLimitTriggerSpeed"` // trigger threshold in Mbps, default 100
	DyLimitSpeed        int    `json:"DyLimitSpeed"`        // speed limit after trigger in Mbps, default 30
	DyLimitTime         int    `json:"DyLimitTime"`         // limit duration in seconds, default 600
	DyLimitWhiteUserID  string `json:"DyLimitWhiteUserID"`  // whitelist user IDs, comma separated
}
