package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneric(t *testing.T) {
	testSigningKey := []byte("testKey")
	token, err := emailConfirmationToken(testSigningKey, "test@test.com", "salty")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}
