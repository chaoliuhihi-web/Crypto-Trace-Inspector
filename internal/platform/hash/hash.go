package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// Text 将多个字段按换行拼接后计算 SHA-256。
// 这里用于 record_hash / chain_hash 等“字段级留痕”场景。
func Text(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			_, _ = h.Write([]byte("\n"))
		}
		_, _ = h.Write([]byte(strings.TrimSpace(p)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// File 读取文件并计算 SHA-256，同时返回文件大小。
// 用于证据快照完整性校验。
func File(path string) (sum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
