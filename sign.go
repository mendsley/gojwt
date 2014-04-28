/*-
 * Copyright 2012-2014 Matthew Endsley
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package gojwt

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

type Claim struct {
	Iss   string `json:"iss"`
	Scope string `json:"scope,omitempty"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
}

func NewClaim(issuer, scope, audience string, now time.Time, duration time.Duration) Claim {
	return Claim{
		Iss:   issuer,
		Scope: scope,
		Aud:   audience,
		Exp:   now.Add(duration).Unix(),
		Iat:   now.Unix(),
	}
}

func SignRSA_SHA256(c Claim, key crypto.PrivateKey) (string, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("Private key of type %T cannot be used for RSA signing", key)
	}

	// encode the header+claim to JWT format
	claimBytes, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("Failed to marshal claim as JSON: %v", err)
	}

	var buffer bytes.Buffer
	buffer.WriteString(encodeHeader("RS256"))
	buffer.WriteRune('.')
	buffer.WriteString(safeEncode(claimBytes))

	// sign the header+claim
	hash := sha256.New()
	hash.Write(buffer.Bytes())

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("RSA signature failed: %v", err)
	}

	// append the signature
	buffer.WriteRune('.')
	buffer.WriteString(safeEncode(signature))

	return buffer.String(), nil
}
