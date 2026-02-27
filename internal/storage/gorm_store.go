package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"easy_proxies/internal/config"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type GORMStore struct {
	db *gorm.DB
}

type nodeModel struct {
	Position  int       `gorm:"not null;index"`
	Name      string    `gorm:"primaryKey;type:text"`
	URI       string    `gorm:"type:text;not null"`
	Port      uint16    `gorm:"not null;default:0"`
	Username  string    `gorm:"type:text;not null;default:''"`
	Password  string    `gorm:"type:text;not null;default:''"`
	Source    string    `gorm:"type:text;not null;default:''"`
	SourceRef string    `gorm:"type:text;not null;default:''"`
	UpdatedAt time.Time `gorm:"not null"`
}

func (nodeModel) TableName() string { return "ep_nodes" }

type settingsModel struct {
	ID             int16     `gorm:"primaryKey"`
	ExternalIP     string    `gorm:"type:text;not null;default:''"`
	ProbeTarget    string    `gorm:"type:text;not null;default:''"`
	SkipCertVerify bool      `gorm:"not null;default:false"`
	UpdatedAt      time.Time `gorm:"not null"`
}

func (settingsModel) TableName() string { return "ep_settings" }

type nodeRuntimeModel struct {
	Tag              string `gorm:"primaryKey;type:text"`
	FailureCount     int    `gorm:"not null;default:0"`
	SuccessCount     int64  `gorm:"not null;default:0"`
	Blacklisted      bool   `gorm:"not null;default:false"`
	BlacklistedUntil *time.Time
	LastError        string `gorm:"type:text;not null;default:''"`
	LastFailure      *time.Time
	LastSuccess      *time.Time
	LastProbeLatency int64     `gorm:"not null;default:0"`
	Available        bool      `gorm:"not null;default:false"`
	InitialCheckDone bool      `gorm:"not null;default:false"`
	UpdatedAt        time.Time `gorm:"not null"`
}

func (nodeRuntimeModel) TableName() string { return "ep_node_runtime" }

type sharedRuntimeModel struct {
	Tag              string `gorm:"primaryKey;type:text"`
	Failures         int    `gorm:"not null;default:0"`
	Blacklisted      bool   `gorm:"not null;default:false"`
	BlacklistedUntil *time.Time
	UpdatedAt        time.Time `gorm:"not null"`
}

func (sharedRuntimeModel) TableName() string { return "ep_shared_runtime" }

func NewGORMStore(driver, dsn string) (*GORMStore, error) {
	if driver == "" {
		return nil, errors.New("storage driver is empty")
	}
	if dsn == "" {
		return nil, errors.New("storage dsn is empty")
	}

	var dialector gorm.Dialector
	switch driver {
	case "postgres", "postgresql":
		dialector = postgres.Open(dsn)
	case "mysql":
		dialector = mysql.Open(dsn)
	case "sqlite", "sqlite3":
		dialector = sqlite.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported storage driver %q", driver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open gorm store: %w", err)
	}
	return &GORMStore{db: db}, nil
}

func (s *GORMStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	sqlDB, err := s.db.DB()
	if err != nil {
		return nil
	}
	return sqlDB.Close()
}

func (s *GORMStore) EnsureSchema(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(
		&nodeModel{},
		&settingsModel{},
		&nodeRuntimeModel{},
		&sharedRuntimeModel{},
	)
}

func (s *GORMStore) LoadNodes(ctx context.Context) ([]config.NodeConfig, error) {
	var rows []nodeModel
	if err := s.db.WithContext(ctx).Order("position asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]config.NodeConfig, 0, len(rows))
	for _, r := range rows {
		out = append(out, config.NodeConfig{
			Name:      r.Name,
			URI:       r.URI,
			Port:      r.Port,
			Username:  r.Username,
			Password:  r.Password,
			Source:    config.NodeSource(r.Source),
			SourceRef: r.SourceRef,
		})
	}
	return out, nil
}

func (s *GORMStore) SaveNodes(ctx context.Context, nodes []config.NodeConfig) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&nodeModel{}).Error; err != nil {
			return err
		}
		for i, n := range nodes {
			row := nodeModel{
				Position:  i,
				Name:      n.Name,
				URI:       n.URI,
				Port:      n.Port,
				Username:  n.Username,
				Password:  n.Password,
				Source:    string(n.Source),
				SourceRef: n.SourceRef,
				UpdatedAt: time.Now(),
			}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *GORMStore) LoadSettings(ctx context.Context) (Settings, bool, error) {
	var row settingsModel
	err := s.db.WithContext(ctx).First(&row, "id = ?", 1).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Settings{}, false, nil
	}
	if err != nil {
		return Settings{}, false, err
	}
	return Settings{
		ExternalIP:     row.ExternalIP,
		ProbeTarget:    row.ProbeTarget,
		SkipCertVerify: row.SkipCertVerify,
	}, true, nil
}

func (s *GORMStore) SaveSettings(ctx context.Context, settings Settings) error {
	row := settingsModel{
		ID:             1,
		ExternalIP:     settings.ExternalIP,
		ProbeTarget:    settings.ProbeTarget,
		SkipCertVerify: settings.SkipCertVerify,
		UpdatedAt:      time.Now(),
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"external_ip", "probe_target", "skip_cert_verify", "updated_at"}),
	}).Create(&row).Error
}

func (s *GORMStore) LoadNodeRuntimeState(ctx context.Context, tag string) (NodeRuntimeState, bool, error) {
	var row nodeRuntimeModel
	err := s.db.WithContext(ctx).First(&row, "tag = ?", tag).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return NodeRuntimeState{}, false, nil
	}
	if err != nil {
		return NodeRuntimeState{}, false, err
	}
	return NodeRuntimeState{
		Tag:              row.Tag,
		FailureCount:     row.FailureCount,
		SuccessCount:     row.SuccessCount,
		Blacklisted:      row.Blacklisted,
		BlacklistedUntil: derefTime(row.BlacklistedUntil),
		LastError:        row.LastError,
		LastFailure:      derefTime(row.LastFailure),
		LastSuccess:      derefTime(row.LastSuccess),
		LastProbeLatency: time.Duration(row.LastProbeLatency) * time.Millisecond,
		Available:        row.Available,
		InitialCheckDone: row.InitialCheckDone,
	}, true, nil
}

func (s *GORMStore) SaveNodeRuntimeState(ctx context.Context, state NodeRuntimeState) error {
	row := nodeRuntimeModel{
		Tag:              state.Tag,
		FailureCount:     state.FailureCount,
		SuccessCount:     state.SuccessCount,
		Blacklisted:      state.Blacklisted,
		BlacklistedUntil: ptrTime(state.BlacklistedUntil),
		LastError:        state.LastError,
		LastFailure:      ptrTime(state.LastFailure),
		LastSuccess:      ptrTime(state.LastSuccess),
		LastProbeLatency: state.LastProbeLatency.Milliseconds(),
		Available:        state.Available,
		InitialCheckDone: state.InitialCheckDone,
		UpdatedAt:        time.Now(),
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "tag"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"failure_count", "success_count", "blacklisted", "blacklisted_until",
			"last_error", "last_failure", "last_success", "last_probe_latency",
			"available", "initial_check_done", "updated_at",
		}),
	}).Create(&row).Error
}

func (s *GORMStore) DeleteNodeRuntimeState(ctx context.Context, tag string) error {
	return s.db.WithContext(ctx).Delete(&nodeRuntimeModel{}, "tag = ?", tag).Error
}

func (s *GORMStore) LoadSharedRuntimeState(ctx context.Context, tag string) (SharedRuntimeState, bool, error) {
	var row sharedRuntimeModel
	err := s.db.WithContext(ctx).First(&row, "tag = ?", tag).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return SharedRuntimeState{}, false, nil
	}
	if err != nil {
		return SharedRuntimeState{}, false, err
	}
	return SharedRuntimeState{
		Tag:              row.Tag,
		Failures:         row.Failures,
		Blacklisted:      row.Blacklisted,
		BlacklistedUntil: derefTime(row.BlacklistedUntil),
	}, true, nil
}

func (s *GORMStore) SaveSharedRuntimeState(ctx context.Context, state SharedRuntimeState) error {
	row := sharedRuntimeModel{
		Tag:              state.Tag,
		Failures:         state.Failures,
		Blacklisted:      state.Blacklisted,
		BlacklistedUntil: ptrTime(state.BlacklistedUntil),
		UpdatedAt:        time.Now(),
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tag"}},
		DoUpdates: clause.AssignmentColumns([]string{"failures", "blacklisted", "blacklisted_until", "updated_at"}),
	}).Create(&row).Error
}

func (s *GORMStore) DeleteSharedRuntimeState(ctx context.Context, tag string) error {
	return s.db.WithContext(ctx).Delete(&sharedRuntimeModel{}, "tag = ?", tag).Error
}

func ptrTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	cpy := t
	return &cpy
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
