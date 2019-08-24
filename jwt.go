package oauth2

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type JwtClaims struct {
	jwt.StandardClaims
	OpenID   string
	ClientID string
	Username string
}

func NewJwtClaims() *JwtClaims {
	return &JwtClaims{}
}

func newJwtToken(claims jwt.Claims, jwtVerifyKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtVerifyKey)
}

func NewAccessToken(claims *JwtClaims, jwtVerifyKey []byte, tokenExpire time.Duration) (string, error) {
	claims.ExpiresAt = time.Now().Add(tokenExpire).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtVerifyKey)
}

func ParseAccessToken(accessToken string, jwtVerifyKey []byte) (claims *JwtClaims, err error) {
	var token *jwt.Token
	token, err = jwt.ParseWithClaims(accessToken, &JwtClaims{}, func(token *jwt.Token) (i interface{}, e error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtVerifyKey, nil
	})
	if token != nil {
		var ok bool
		if claims, ok = token.Claims.(*JwtClaims); ok && token.Valid {
			return claims, nil
		}
	}
	return
}

func EncodeOpenID(uuid, clientId string, secret []byte) string {
	//jwt.DecodeSegment()
	return ""
}

func DesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData = PKCS5Padding(origData, block.BlockSize())
	// origData = ZeroPadding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	// crypted := origData
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil

}
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func DesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
