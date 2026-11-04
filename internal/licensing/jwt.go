package licensing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const Issuer = "license-server"

// Signer 负责 access / refresh JWT 的签发与校验(EdDSA).
type Signer struct {
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	Now        func() time.Time // 可注入固定时钟(测试)
}

// NewSigner 构造签名器.
func NewSigner(priv ed25519.PrivateKey, accessTTL, refreshTTL time.Duration) *Signer {
	return &Signer{
		priv:       priv,
		pub:        priv.Public().(ed25519.PublicKey),
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
		Now:        time.Now,
	}
}

func (s *Signer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Pubkey 返回 Ed25519 公钥.
func (s *Signer) Pubkey() ed25519.PublicKey { return s.pub }

func randomJTI() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SignAccess 签发 access JWT.
// exp = min(now+AccessTTL, license 到期):断网离线宽限不超过 license 本身有效期.
// 返回 token、exp(unix 秒).
func (s *Signer) SignAccess(licenseID, machineHash string, features json.RawMessage, licenseExp int64) (token string, exp int64, err error) {
	now := s.now()
	exp = now.Add(s.AccessTTL).Unix()
	if licenseExp < exp {
		exp = licenseExp
	}
	var feat any = map[string]any{}
	if len(features) > 0 {
		_ = json.Unmarshal(features, &feat)
	}
	jti, err := randomJTI()
	if err != nil {
		return "", 0, err
	}
	claims := jwt.MapClaims{
		"iss":      Issuer,
		"typ":      "access",
		"sub":      licenseID,
		"mhash":    machineHash,
		"lic_exp":  licenseExp,
		"features": feat,
		"iat":      now.Unix(),
		"exp":      exp,
		"jti":      jti,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token, err = t.SignedString(s.priv)
	return token, exp, err
}

// SignRefresh 签发 refresh JWT. 返回 token、exp(unix 秒)与 jti
// (jti 需写入 activations.current_refresh_jti 以支持轮换重用检测).
func (s *Signer) SignRefresh(licenseID, machineHash string) (token string, exp int64, jti string, err error) {
	now := s.now()
	exp = now.Add(s.RefreshTTL).Unix()
	jti, err = randomJTI()
	if err != nil {
		return "", 0, "", err
	}
	claims := jwt.MapClaims{
		"iss": Issuer,
		"typ": "refresh",
		"sub": licenseID,
		"mhash": machineHash,
		"iat":  now.Unix(),
		"exp":  exp,
		"jti":  jti,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token, err = t.SignedString(s.priv)
	return token, exp, jti, err
}

// Parse 验签并解析 JWT(仅接受 EdDSA). 返回无效错误时调用方映射为 401.
func (s *Signer) Parse(token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	opt := jwt.WithTimeFunc(s.now)
	t, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("签名算法不符")
		}
		return s.pub, nil
	}, opt)
	if err != nil || !t.Valid {
		return nil, fmt.Errorf("token 无效或已过期")
	}
	return claims, nil
}
