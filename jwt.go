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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Purchase struct {
	CurrencyCode string `json:"currencyCode"`
	Price        string `json:"price"`
	Name         string `json:"name"`
	SellerData   string `json:"sellerData"`
	Description  string `json:"description"`
}

var (
	encodedHeader = safeEncode([]byte("{\"alg\":\"HS256\"}"))
)

func Encode(sellerId, secret string, purchase *Purchase, expiration time.Duration) (jwt string, err error) {

	var claim struct {
		Iss     string   `json:"iss"`
		Aud     string   `json:"aud"`
		Typ     string   `json:"typ"`
		Iat     uint64   `json:"iat"`
		Exp     uint64   `json:"exp"`
		Request Purchase `json:"request"`
	}

	now := time.Now().Unix()

	claim.Iss = sellerId
	claim.Aud = "Google"
	claim.Typ = "google/payments/inapp/item/v1"
	claim.Iat = uint64(now)
	claim.Exp = claim.Iat + uint64(expiration.Seconds()+0.5)
	claim.Request = *purchase

	payloadData, err := json.Marshal(claim)
	if err != nil {
		return "", err
	}

	signingString := encodedHeader + "." + safeEncode(payloadData)

	sign := hmac.New(sha256.New, []byte(secret))
	sign.Write([]byte(signingString))

	return signingString + "." + safeEncode(sign.Sum(nil)), nil
}

func Verify(jwt, secret string) (purchase *Purchase, orderId string, err error) {

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, "", errors.New("Malformed jwt: " + jwt)
	}

	// validate header
	headerJson, err := safeDecode(parts[0])
	if err != nil {
		return nil, "", errors.New("Malformed jwt header: " + jwt)
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err = json.Unmarshal(headerJson, &header); err != nil {
		return nil, "", errors.New("Malformed jwt header: " + jwt)
	}

	if header.Alg != "HS256" {
		return nil, "", errors.New("Cannot verify non HS256 jwt algorithm: " + header.Alg)
	}

	// verify signature
	reportedSignature, err := safeDecode(parts[2])
	if err != nil {
		return nil, "", errors.New("Malformed jwt signature: " + jwt)
	}

	sign := hmac.New(sha256.New, []byte(secret))
	sign.Write([]byte(parts[0] + "." + parts[1]))
	signature := sign.Sum(nil)

	if !bytes.Equal(reportedSignature, signature) {
		return nil, "", errors.New("Signature mismatch on jwt: " + jwt)
	}

	// parse claim
	claimJson, err := safeDecode(parts[1])
	if err != nil {
		return nil, "", errors.New("Malformed jwt claim: " + jwt)
	}

	var claim struct {
		Iss      string   `json:"iss"`
		Aud      string   `json:"aus"`
		Typ      string   `json:"typ"`
		Iat      uint64   `json:"iat"`
		Exp      uint64   `json:"exp"`
		Request  Purchase `json:"request"`
		Response struct {
			OrderId string `json:"orderId"`
		} `json:"response"`
	}

	if err := json.Unmarshal(claimJson, &claim); err != nil {
		return nil, "", errors.New("Malformed jwt claim: " + jwt)
	}

	return &claim.Request, claim.Response.OrderId, nil
}
