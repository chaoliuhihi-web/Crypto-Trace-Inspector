package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"sort"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrator 负责执行内嵌 SQL 迁移脚本。
type Migrator struct {
	db *sql.DB
}

func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{db: db}
}

// Up 依次执行 migrations 目录下的 SQL 文件。
// 通过文件名字典序控制迁移顺序（例如 001_xxx.sql -> 002_xxx.sql）。
func (m *Migrator) Up(ctx context.Context) error {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		path := filepath.Join("migrations", entry.Name())
		raw, err := migrationFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		if _, err := m.db.ExecContext(ctx, string(raw)); err != nil {
			return fmt.Errorf("exec migration %s: %w", entry.Name(), err)
		}
	}

	return nil
}
