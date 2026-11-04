// Package store 封装 SQLite 持久层:建表/迁移与 licenses、activations 的全部查询.
// 所有方法接收 ctx,调用方透传请求上下文以支持取消与超时.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// LicenseRow licenses 表整行.
type LicenseRow struct {
	ID          string
	KeyHash     string
	Customer    string
	Seats       int
	ExpiresAt   int64
	Features    string
	Status      string
	CreatedAt   int64
	ProductID   string
	ProductName string
}

// MachineView 单台激活设备视图.
type MachineView struct {
	MachineHash string `json:"machine_hash"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
}

// LicenseView 管理 API 返回的授权视图(Used 为席位占用数).
type LicenseView struct {
	LicenseID   string          `json:"license_id"`
	Customer    string          `json:"customer"`
	Seats       int             `json:"seats"`
	Used        int             `json:"used"`
	ExpiresAt   int64           `json:"expires_at"`
	Status      string          `json:"status"`
	Features    json.RawMessage `json:"features"`
	CreatedAt   int64           `json:"created_at"`
	ProductID   string          `json:"product_id"`
	ProductName string          `json:"product_name"`
}

// Store SQLite 持久层句柄.
type Store struct {
	db *sql.DB
}

// New 用现有 *sql.DB 构造并完成建表/迁移(幂等).
func New(db *sql.DB) *Store {
	if err := initDB(db); err != nil {
		// 建表失败时延迟到第一次查询报错;正常路径不会发生.
		panic(fmt.Sprintf("store: 初始化 schema 失败: %v", err))
	}
	return &Store{db: db}
}

// Open 打开 SQLite 文件并完成 PRAGMA/建表/迁移.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	// 单写者模型:modernc/sqlite 多连接并发写会 SQLITE_BUSY,限 1 连接最稳.
	db.SetMaxOpenConns(1)
	if err := initDB(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close 关闭底层连接.
func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS licenses (
	id         TEXT PRIMARY KEY,
	key_hash   TEXT UNIQUE NOT NULL,
	customer   TEXT NOT NULL,
	seats      INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	features   TEXT NOT NULL DEFAULT '{}',
	status     TEXT NOT NULL DEFAULT 'active',
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_licenses_key_hash ON licenses(key_hash);
CREATE TABLE IF NOT EXISTS activations (
	license_id   TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
	machine_hash TEXT NOT NULL,
	first_seen   INTEGER NOT NULL,
	last_seen    INTEGER NOT NULL,
	PRIMARY KEY (license_id, machine_hash)
);
CREATE TABLE IF NOT EXISTS products (
	id           TEXT PRIMARY KEY,
	name         TEXT UNIQUE NOT NULL,
	features     TEXT NOT NULL DEFAULT '{}',
	default_days INTEGER NOT NULL DEFAULT 365,
	default_seats INTEGER NOT NULL DEFAULT 5,
	created_at   INTEGER NOT NULL
);
`

func initDB(db *sql.DB) error {
	for _, p := range []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`PRAGMA foreign_keys=ON;`,
	} {
		if _, err := db.Exec(p); err != nil {
			return err
		}
	}
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	return migrate(db)
}

// migrate 幂等升级: v2 加 current_refresh_jti;v3 加 licenses.product_id/product_name(产品快照).
func migrate(db *sql.DB) error {
	stmts := []string{
		`ALTER TABLE activations ADD COLUMN current_refresh_jti TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE licenses ADD COLUMN product_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE licenses ADD COLUMN product_name TEXT NOT NULL DEFAULT ''`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			// 列已存在则忽略,其余错误向上抛.
			if !strings.Contains(err.Error(), "duplicate column") {
				return err
			}
		}
	}
	return nil
}

const licenseCols = `id,key_hash,customer,seats,expires_at,features,status,created_at,product_id,product_name`

func scanLicense(row interface{ Scan(...any) error }) (*LicenseRow, error) {
	var l LicenseRow
	err := row.Scan(&l.ID, &l.KeyHash, &l.Customer, &l.Seats, &l.ExpiresAt, &l.Features, &l.Status, &l.CreatedAt, &l.ProductID, &l.ProductName)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// GetLicenseByHash 按 license_key 的 SHA256 查询. 未命中返回 (nil, nil).
func (s *Store) GetLicenseByHash(ctx context.Context, hash string) (*LicenseRow, error) {
	return scanLicense(s.db.QueryRowContext(ctx,
		`SELECT `+licenseCols+` FROM licenses WHERE key_hash=?`, hash))
}

// GetLicenseByID 按 license_id 查询. 未命中返回 (nil, nil).
func (s *Store) GetLicenseByID(ctx context.Context, id string) (*LicenseRow, error) {
	return scanLicense(s.db.QueryRowContext(ctx,
		`SELECT `+licenseCols+` FROM licenses WHERE id=?`, id))
}

// CreateLicense 插入新 license(key_hash UNIQUE 冲突由调用方重试).
func (s *Store) CreateLicense(ctx context.Context, l *LicenseRow) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO licenses(id,key_hash,customer,seats,expires_at,features,status,created_at,product_id,product_name) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		l.ID, l.KeyHash, l.Customer, l.Seats, l.ExpiresAt, l.Features, l.Status, l.CreatedAt, l.ProductID, l.ProductName)
	return err
}

// SetStatus 吊销/恢复. 返回受影响行数(0 = 不存在).
func (s *Store) SetStatus(ctx context.Context, id, status string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE licenses SET status=? WHERE id=?`, status, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Extend 直接改写到期时间.
func (s *Store) Extend(ctx context.Context, id string, newExp int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE licenses SET expires_at=? WHERE id=?`, newExp, id)
	return err
}

// UpdateLicense 修改客户名/席位数.
func (s *Store) UpdateLicense(ctx context.Context, id, customer string, seats int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE licenses SET customer=?, seats=? WHERE id=?`, customer, seats, id)
	return err
}

// UpdateFeatures 修改功能标记 JSON.
func (s *Store) UpdateFeatures(ctx context.Context, id, features string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE licenses SET features=? WHERE id=?`, features, id)
	return err
}

// DeleteLicense 彻底删除 license 及其激活记录. 返回删除行数(0 = 不存在).
func (s *Store) DeleteLicense(ctx context.Context, id string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM activations WHERE license_id=?`, id); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM licenses WHERE id=?`, id)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// CountActivations 席位占用数.
func (s *Store) CountActivations(ctx context.Context, licenseID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM activations WHERE license_id=?`, licenseID).Scan(&n)
	return n, err
}

// ActivationExists 设备是否已绑定.
func (s *Store) ActivationExists(ctx context.Context, licenseID, machineHash string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM activations WHERE license_id=? AND machine_hash=?`, licenseID, machineHash).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// TouchActivation 同机重复激活:幂等刷新 last_seen.
func (s *Store) TouchActivation(ctx context.Context, licenseID, machineHash string, now int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE activations SET last_seen=? WHERE license_id=? AND machine_hash=?`, now, licenseID, machineHash)
	return err
}

// InsertActivation 新增绑定.
func (s *Store) InsertActivation(ctx context.Context, licenseID, machineHash string, now int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO activations(license_id,machine_hash,first_seen,last_seen) VALUES(?,?,?,?)`,
		licenseID, machineHash, now, now)
	return err
}

// ListMachines 某 license 全部激活设备.
func (s *Store) ListMachines(ctx context.Context, licenseID string) ([]*MachineView, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT machine_hash,first_seen,last_seen FROM activations WHERE license_id=? ORDER BY first_seen`, licenseID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*MachineView
	for rows.Next() {
		var m MachineView
		if err := rows.Scan(&m.MachineHash, &m.FirstSeen, &m.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, &MachineView{MachineHash: m.MachineHash, FirstSeen: m.FirstSeen, LastSeen: m.LastSeen})
	}
	if out == nil {
		out = []*MachineView{}
	}
	return out, rows.Err()
}

// UnbindAll 解绑全部设备. 返回解绑行数.
func (s *Store) UnbindAll(ctx context.Context, licenseID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM activations WHERE license_id=?`, licenseID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Kick 踢单台设备. 返回删除行数.
func (s *Store) Kick(ctx context.Context, licenseID, machineHash string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM activations WHERE license_id=? AND machine_hash=?`, licenseID, machineHash)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CurrentRefreshJTI 读取设备当前有效的 refresh jti. 未绑定返回 (nil, nil).
func (s *Store) CurrentRefreshJTI(ctx context.Context, licenseID, machineHash string) (*string, error) {
	var jti string
	err := s.db.QueryRowContext(ctx,
		`SELECT current_refresh_jti FROM activations WHERE license_id=? AND machine_hash=?`, licenseID, machineHash).Scan(&jti)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &jti, nil
}

// SetActivationRefresh 轮换后写入新 refresh jti 并刷新 last_seen.
func (s *Store) SetActivationRefresh(ctx context.Context, licenseID, machineHash, jti string, now int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE activations SET current_refresh_jti=?, last_seen=? WHERE license_id=? AND machine_hash=?`,
		jti, now, licenseID, machineHash)
	return err
}

// sortColumns 台账可排序字段白名单(键来自前端,值拼进 SQL,故必须白名单).
var sortColumns = map[string]string{
	"customer":   "l.customer",
	"license_id": "l.id",
	"seats":      "l.seats",
	"expires_at": "l.expires_at",
	"status":     "l.status",
	"created_at": "l.created_at",
}

// SortColumn 返回排序白名单映射(未命中回退 created_at).
func SortColumn(key string) string {
	if col, ok := sortColumns[key]; ok {
		return col
	}
	return "l.created_at"
}

// StatsRow 概览统计.
type StatsRow struct {
	Total    int `json:"total"`
	Active   int `json:"active"`
	Expiring int `json:"expiring"`
	Expired  int `json:"expired"`
	Revoked  int `json:"revoked"`
	Seats    int `json:"seats"`
	Used     int `json:"used"`
}

// Stats 汇总统计(供管理台概览页).
func (s *Store) Stats(ctx context.Context, now int64) (*StatsRow, error) {
	var r StatsRow
	err := s.db.QueryRowContext(ctx, `SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status=? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status=? AND expires_at<=? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status=? AND expires_at>? AND expires_at<=? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(seats),0),
		(SELECT COUNT(*) FROM activations)
		FROM licenses`,
		"revoked", "active", now, "active", now, now+7*86400).
		Scan(&r.Total, &r.Revoked, &r.Expired, &r.Expiring, &r.Seats, &r.Used)
	if err != nil {
		return nil, err
	}
	r.Active = r.Total - r.Revoked - r.Expired
	return &r, nil
}

// ListPage 分页台账(带席位占用子查询,避免 N+1). dir 只允许 ASC/DESC,由调用方归一.
func (s *Store) ListPage(ctx context.Context, q, status string, page, pageSize int, sortKey, dir string, now int64) ([]*LicenseView, int, error) {
	where := []string{"1=1"}
	args := []any{}
	if q != "" {
		where = append(where, "(l.customer LIKE ? OR l.id LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like)
	}
	switch status {
	case "revoked":
		where = append(where, "l.status=?")
		args = append(args, "revoked")
	case "expired":
		where = append(where, "l.status=? AND l.expires_at<=?")
		args = append(args, "active", now)
	case "expiring":
		where = append(where, "l.status=? AND l.expires_at>? AND l.expires_at<=?")
		args = append(args, "active", now, now+7*86400)
	case "active":
		where = append(where, "l.status=? AND l.expires_at>?")
		args = append(args, "active", now)
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM licenses l WHERE `+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	if dir != "ASC" {
		dir = "DESC"
	}
	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, `SELECT l.id,l.customer,l.seats,l.expires_at,l.features,l.status,l.created_at,l.product_id,l.product_name,
		(SELECT COUNT(*) FROM activations a WHERE a.license_id=l.id)
		FROM licenses l WHERE `+whereSQL+` ORDER BY `+SortColumn(sortKey)+` `+dir+` LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	out := []*LicenseView{}
	for rows.Next() {
		var l LicenseRow
		var used int
		if err := rows.Scan(&l.ID, &l.Customer, &l.Seats, &l.ExpiresAt, &l.Features, &l.Status, &l.CreatedAt, &l.ProductID, &l.ProductName, &used); err != nil {
			return nil, 0, err
		}
		feat := l.Features
		if feat == "" {
			feat = "{}"
		}
		out = append(out, &LicenseView{
			LicenseID: l.ID, Customer: l.Customer, Seats: l.Seats, Used: used,
			ExpiresAt: l.ExpiresAt, Status: l.Status,
			Features: json.RawMessage(feat), CreatedAt: l.CreatedAt,
			ProductID: l.ProductID, ProductName: l.ProductName,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// ToView 单行转授权视图(含席位占用).
func (s *Store) ToView(ctx context.Context, l *LicenseRow) (*LicenseView, error) {
	used, err := s.CountActivations(ctx, l.ID)
	if err != nil {
		return nil, err
	}
	feat := l.Features
	if feat == "" {
		feat = "{}"
	}
	return &LicenseView{
		LicenseID: l.ID, Customer: l.Customer, Seats: l.Seats, Used: used,
		ExpiresAt: l.ExpiresAt, Status: l.Status,
		Features: json.RawMessage(feat), CreatedAt: l.CreatedAt,
		ProductID: l.ProductID, ProductName: l.ProductName,
	}, nil
}

// ---------------------------------------------------------------------------
// 数据洞察(Dashboard): 签发趋势 / 产品分布 / 即将到期
// ---------------------------------------------------------------------------

// TrendPoint 单日签发数量.
type TrendPoint struct {
	Day   string `json:"day"` // YYYY-MM-DD
	Count int    `json:"count"`
}

// IssueTrend 最近 days 天的每日签发数量(缺签发日不补零,由前端渲染).
func (s *Store) IssueTrend(ctx context.Context, days int) ([]TrendPoint, error) {
	if days < 1 || days > 365 {
		days = 30
	}
	since := time.Now().AddDate(0, 0, -days+1).Truncate(24 * time.Hour).Unix()
	rows, err := s.db.QueryContext(ctx, `SELECT date(created_at,'unixepoch') AS day, COUNT(*)
		FROM licenses WHERE created_at>=? GROUP BY day ORDER BY day`, since)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []TrendPoint{}
	for rows.Next() {
		var p TrendPoint
		if err := rows.Scan(&p.Day, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProductCount 按产品统计的 license 数量.
type ProductCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// LicensesByProduct 按产品聚合 license 数量(含未关联产品).
func (s *Store) LicensesByProduct(ctx context.Context) ([]ProductCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(NULLIF(product_name,''),'未关联产品') AS name, COUNT(*)
		FROM licenses GROUP BY name ORDER BY COUNT(*) DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []ProductCount{}
	for rows.Next() {
		var p ProductCount
		if err := rows.Scan(&p.Name, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ExpiringSoon 即将到期(7 天内)的 active 授权,按到期时间升序.
// 注意: 先收完结果集再逐行 ToView —— MaxOpenConns(1) 下迭代中再查询会死锁.
func (s *Store) ExpiringSoon(ctx context.Context, now int64, limit int) ([]*LicenseView, error) {
	if limit < 1 || limit > 50 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+licenseCols+`
		FROM licenses WHERE status='active' AND expires_at>? AND expires_at<=?
		ORDER BY expires_at LIMIT ?`, now, now+7*86400, limit)
	if err != nil {
		return nil, err
	}
	var ls []*LicenseRow
	for rows.Next() {
		l, err := scanLicense(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		ls = append(ls, l)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	out := []*LicenseView{}
	for _, l := range ls {
		v, err := s.ToView(ctx, l)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// 产品目录: 签发 license 时按产品带入默认 features / 天数 / 席位.
// 产品只是签发侧的模板;签发后 license 持有 features 快照,与产品后续变更无关.
// ---------------------------------------------------------------------------

// ProductRow products 表整行.
type ProductRow struct {
	ID           string
	Name         string
	Features     string
	DefaultDays  int
	DefaultSeats int
	CreatedAt    int64
}

// ProductView 管理 API 返回的产品视图.
type ProductView struct {
	ProductID    string          `json:"product_id"`
	Name         string          `json:"name"`
	Features     json.RawMessage `json:"features"`
	DefaultDays  int             `json:"default_days"`
	DefaultSeats int             `json:"default_seats"`
	CreatedAt    int64           `json:"created_at"`
}

func (p *ProductRow) View() *ProductView {
	feat := p.Features
	if feat == "" {
		feat = "{}"
	}
	return &ProductView{
		ProductID: p.ID, Name: p.Name,
		Features: json.RawMessage(feat),
		DefaultDays: p.DefaultDays, DefaultSeats: p.DefaultSeats,
		CreatedAt: p.CreatedAt,
	}
}

// CreateProduct 新增产品(name UNIQUE 冲突由调用方处理).
func (s *Store) CreateProduct(ctx context.Context, p *ProductRow) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO products(id,name,features,default_days,default_seats,created_at) VALUES(?,?,?,?,?,?)`,
		p.ID, p.Name, p.Features, p.DefaultDays, p.DefaultSeats, p.CreatedAt)
	return err
}

// ListProducts 全部产品,按创建时间倒序.
func (s *Store) ListProducts(ctx context.Context) ([]*ProductView, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,features,default_days,default_seats,created_at FROM products ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []*ProductView{}
	for rows.Next() {
		var p ProductRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Features, &p.DefaultDays, &p.DefaultSeats, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p.View())
	}
	if out == nil {
		out = []*ProductView{}
	}
	return out, rows.Err()
}

// GetProductByID 按 id 查询. 未命中返回 (nil, nil).
func (s *Store) GetProductByID(ctx context.Context, id string) (*ProductRow, error) {
	var p ProductRow
	err := s.db.QueryRowContext(ctx,
		`SELECT id,name,features,default_days,default_seats,created_at FROM products WHERE id=?`, id).
		Scan(&p.ID, &p.Name, &p.Features, &p.DefaultDays, &p.DefaultSeats, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdateProduct 修改产品(模板变更不影响已签发的 license 快照).
func (s *Store) UpdateProduct(ctx context.Context, id, name, features string, days, seats int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE products SET name=?, features=?, default_days=?, default_seats=? WHERE id=?`,
		name, features, days, seats, id)
	return err
}

// DeleteProduct 删除产品. 返回删除行数(0 = 不存在). 已签发 license 不受影响.
func (s *Store) DeleteProduct(ctx context.Context, id string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM products WHERE id=?`, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
