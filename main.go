package main

import (
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	iss = "humdip.com"

	userTokenExpiry              = time.Minute * 10
	emailConfirmationTokenExpiry = time.Hour
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
			ExpiresAt: time.Now().Add(emailConfirmationTokenExpiry).Unix(),
			Issuer:    iss,
		},
	}

	return sign(claims, signingKey)
}

type APITokenClaims struct {
	jwt.StandardClaims
}

func apiToken(signingKey []byte, userID string) (string, error) {
	claims := APITokenClaims{
		jwt.StandardClaims{
			Issuer:  iss,
			Subject: userID,
		},
	}

	return sign(claims, signingKey)
}

func userToken(signingKey []byte, userID string) (string, error) {
	claims := APITokenClaims{
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(userTokenExpiry).Unix(),
			Issuer:    iss,
			Subject:   userID,
		},
	}

	return sign(claims, signingKey)
}

func sign(claims jwt.Claims, signingKey []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(signingKey)
}
