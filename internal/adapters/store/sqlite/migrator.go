package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"time"
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

// ensureMigrationsTable 创建 schema_migrations 表（如不存在）。
//
// 早期版本为了简单，所有迁移脚本都写成“可重复执行”的形式（CREATE IF NOT EXISTS）。
// 随着功能增强，后续会出现需要“只执行一次”的迁移（例如重建表以扩展 CHECK 枚举）。
// 因此这里引入一个最小的迁移记录表，用来避免重复执行已经应用过的脚本。
func (m *Migrator) ensureMigrationsTable(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name TEXT PRIMARY KEY,
			applied_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

func (m *Migrator) isMigrationApplied(ctx context.Context, name string) (bool, error) {
	var tmp string
	err := m.db.QueryRowContext(ctx, `
		SELECT name
		FROM schema_migrations
		WHERE name = ?
		LIMIT 1
	`, name).Scan(&tmp)
	if err == nil {
		return true, nil
	}
	if err == sql.ErrNoRows {
		return false, nil
	}
	return false, fmt.Errorf("query schema_migrations: %w", err)
}

func (m *Migrator) markMigrationApplied(ctx context.Context, name string) error {
	_, err := m.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO schema_migrations(name, applied_at)
		VALUES(?, ?)
	`, name, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("insert schema_migrations: %w", err)
	}
	return nil
}

// Up 依次执行 migrations 目录下的 SQL 文件。
// 通过文件名字典序控制迁移顺序（例如 001_xxx.sql -> 002_xxx.sql）。
func (m *Migrator) Up(ctx context.Context) error {
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return err
	}

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

		name := entry.Name()
		applied, err := m.isMigrationApplied(ctx, name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		path := filepath.Join("migrations", entry.Name())
		raw, err := migrationFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		if _, err := m.db.ExecContext(ctx, string(raw)); err != nil {
			return fmt.Errorf("exec migration %s: %w", entry.Name(), err)
		}

		if err := m.markMigrationApplied(ctx, name); err != nil {
			return err
		}
	}

	return nil
}
