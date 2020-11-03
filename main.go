package main

import (
	"fmt"
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

func validateAuthToken(tokenStr string, signingKey []byte) (userID string, err error) {
	claims := AuthTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		// All tokens are signed with HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Invalid Token: Unexpected signing method: %v", token.Header["alg"])
		}
		return signingKey, nil
	})

	if err != nil {
		// invalid token, try and typecast the error
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return "", fmt.Errorf("Invalid Token: token is malformed")
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				// Token is either expired (exp claim) or not active yet (iat claim)
				return "", fmt.Errorf("Invalid token: token has expired")
			}
		}
		return "", fmt.Errorf("Invalid token: parsing error")
	}

	if token.Valid {
		switch claims.Type {
		case tokenTypeAPIAuth:
			return claims.Subject, nil
		case tokenTypeUserAuth:
			return claims.Subject, nil
		default:
			return "", fmt.Errorf("Invalid token: unrecognised type %v", claims.Type)
		}
	}
	return "", fmt.Errorf("Invalid token")
}
