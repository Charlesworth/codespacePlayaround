package main

import (
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	iss = "humdip.com"
)

func main() {
	mySigningKey := []byte("testKey")
	token, err := emailConfirmationToken(mySigningKey, "test@test.com", "salty")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf(token)
}

type EmailConfirmationTokenClaims struct {
	Email string `json:"email"`
	Salt  string `json:"salt"`
	jwt.StandardClaims
}

func emailConfirmationToken(signingKey []byte, email string, salt string) (string, error) {
	claims := EmailConfirmationTokenClaims{
		email,
		salt,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Issuer:    iss,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

type APITokenClaims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

func apiToken(signingKey []byte, userID string) (string, error) {
	claims := APITokenClaims{
		userID,
		jwt.StandardClaims{
			Issuer: iss,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

type UserTokenClaims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

func userToken(signingKey []byte, userID string) (string, error) {
	claims := APITokenClaims{
		userID,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 10).Unix(),
			Issuer:    iss,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}
