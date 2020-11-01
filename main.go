package main

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	issuer = "humdip.com"

	tokenTypeUserAuth = "au"
	tokenTypeAPIAuth  = "aa"

	userTokenExpiry              = time.Minute * 10
	emailConfirmationTokenExpiry = time.Hour
)

// EmailConfirmationTokenClaims are the custom claims used in the email confirmation token
type EmailConfirmationTokenClaims struct {
	Email string `json:"email"`
	Salt  string `json:"salt"`
	jwt.StandardClaims
}

func emailConfirmationToken(signingKey []byte, email string, salt string) (string, error) {
	return signToken(
		EmailConfirmationTokenClaims{
			email,
			salt,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(emailConfirmationTokenExpiry).Unix(),
				Issuer:    issuer,
			},
		},
		signingKey,
	)
}

// AuthTokenClaims are the custom claims used in auth tokens to discern the auth token type
type AuthTokenClaims struct {
	Type string `json:"type"`
	jwt.StandardClaims
}

func apiToken(signingKey []byte, userID string) (string, error) {
	return signToken(
		AuthTokenClaims{
			tokenTypeAPIAuth,
			jwt.StandardClaims{
				Issuer:  issuer,
				Subject: userID,
			},
		},
		signingKey,
	)
}

func userToken(signingKey []byte, userID string) (string, error) {
	return signToken(
		AuthTokenClaims{
			tokenTypeAPIAuth,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(userTokenExpiry).Unix(),
				Issuer:    issuer,
				Subject:   userID,
			},
		},
		signingKey,
	)
}

func signToken(claims jwt.Claims, signingKey []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(signingKey)
}
