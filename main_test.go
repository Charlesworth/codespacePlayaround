package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmailConfirmationToken(t *testing.T) {
	testSigningKey := []byte("testKey")
	token, err := emailConfirmationToken(testSigningKey, "test@test.com", "salty")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestUserToken(t *testing.T) {
	testSigningKey := []byte("testKey")
	testUserID := "abc123"
	token, err := userToken(testSigningKey, testUserID)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	resultUserID, err := validateAuthToken(token, testSigningKey)
	assert.NoError(t, err)
	assert.Equal(t, testUserID, resultUserID)
}
