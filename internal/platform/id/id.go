package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// New 生成带前缀的简易唯一 ID：
// prefix + 毫秒时间戳 + 随机后缀。
// 这种格式便于日志阅读，也基本满足本地场景下的唯一性。
func New(prefix string) string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("%s_%d_%s", prefix, time.Now().UnixMilli(), hex.EncodeToString(buf))
}
