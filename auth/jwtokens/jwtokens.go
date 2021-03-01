package jwtokens

import (
	"fmt"
	"os"
	"time"

	b64 "encoding/base64"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// TokenPair is a struct that just consists of an access and a refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// GiveTokens creates a pair of Access and Refresh JWTs
func GiveTokens(userID uuid.UUID) (TokenPair, string, error) {
	tokenID := uuid.NewString()
	accessToken := jwt.New(jwt.SigningMethodHS512)
	claims := accessToken.Claims.(jwt.MapClaims)
	claims["user_id"] = userID
	claims["token_id"] = tokenID
	claims["exp"] = time.Now().Add(time.Minute * 10).Unix()
	// Can add any necessary user info as other claims
	at, err := accessToken.SignedString([]byte(os.Getenv("AUTH_SECRET")))
	if err != nil {
		return TokenPair{}, "", err
	}

	refreshToken := jwt.New(jwt.SigningMethodHS512)
	claims = refreshToken.Claims.(jwt.MapClaims)
	claims["token_id"] = tokenID
	claims["exp"] = time.Now().Add(time.Hour * 12).Unix()
	rt, err := refreshToken.SignedString([]byte(os.Getenv("AUTH_SECRET")))
	if err != nil {
		return TokenPair{}, "", err
	}

	at = b64.StdEncoding.EncodeToString([]byte(at))
	rt = b64.StdEncoding.EncodeToString([]byte(rt))

	return TokenPair{AccessToken: at, RefreshToken: rt}, tokenID, nil
}

// CheckTokens returns user ID and token ID if the tokens are valid
func CheckTokens(tokens TokenPair) (string, string, error) {
	// Get access token claims
	data, err := b64.StdEncoding.DecodeString(tokens.AccessToken)
	if err != nil {
		return "", "", err
	}
	at, err := jwt.Parse(string(data), keyFunc)
	if err != nil && err.Error() != "Token is expired" {
		return "", "", err
	}
	atClaims, atOk := at.Claims.(jwt.MapClaims)

	// Get refresh token claims
	data, err = b64.StdEncoding.DecodeString(tokens.RefreshToken)
	if err != nil {
		return "", "", err
	}
	rt, err := jwt.Parse(string(data), keyFunc)
	if err != nil {
		return "", "", err
	}
	rtClaims, rtOk := rt.Claims.(jwt.MapClaims)

	// Check the tokens
	if !atOk || !rtOk {
		return "", "", fmt.Errorf("Provided tokens aren't ok")
	}
	if atClaims["token_id"] != rtClaims["token_id"] {
		return "", "", fmt.Errorf("Provided tokens weren't issued together")
	}

	// Get user and token ID from tokens
	userID := fmt.Sprintf("%v", atClaims["user_id"])
	tokenID := fmt.Sprintf("%v", rtClaims["token_id"])

	return userID, tokenID, nil
}

func keyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}
	return []byte(os.Getenv("AUTH_SECRET")), nil
}
