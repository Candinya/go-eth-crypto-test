package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
	"os"
)

func main() {

	r := bufio.NewReader(os.Stdin)

	privateKeyHex := GetInput("Input PrivateKey (0x...): ", r)

	//if len(privateKeyHex) != 66 {
	//	privateKeyHex = "0xb8964e3f877148013525c0b97f2bfd44e9b0a99fe4e6a7bb89c96473e854f378"
	//}

	// privateKeyHex := "0xb8964e3f877148013525c0b97f2bfd44e9b0a99fe4e6a7bb89c96473e854f378"

	// 0xb8964e3f877148013525c0b97f2bfd44e9b0a99fe4e6a7bb89c96473e854f378
	// 64 Chars, 256 bit length
	// Should be `keccak256` calc result

	// Drop first "0x"
	privateKeyHex = privateKeyHex[2:]

	fmt.Println("Your private key (without 0x prefix): ")
	fmt.Println(privateKeyHex)
	fmt.Println()

	var pvk ecdsa.PrivateKey

	pvk.D, _ = new (big.Int).SetString(privateKeyHex, 16)
	pvk.PublicKey.Curve = secp256k1.S256()
	pvk.PublicKey.X, pvk.PublicKey.Y = pvk.PublicKey.Curve.ScalarBaseMult(pvk.D.Bytes())

	pubkey := elliptic.Marshal(secp256k1.S256(), pvk.X, pvk.Y)

	fmt.Println("Your public key (with 04 prefix): ")
	fmt.Println(hex.EncodeToString(pubkey))
	fmt.Println()

	// 0453f414917174914630d4bce2c7275628e12c73bdcfa1213d1448d4646f8fad285d03068387f6c4752e31e7192569e3fc9d2e2eb27af07affd84cd176e6d01ce8
	//   53f414917174914630d4bce2c7275628e12c73bdcfa1213d1448d4646f8fad285d03068387f6c4752e31e7192569e3fc9d2e2eb27af07affd84cd176e6d01ce8
	// 128 Chars, 512 bit length
	// 04 means uncompressed key
	// if it is 02, means compressed

	ethAddr := crypto.PubkeyToAddress(pvk.PublicKey)

	fmt.Println("Your ETH address: ")
	fmt.Println(ethAddr.String())
	fmt.Println()

	// 0xFa44681FFAF69127A49ceDDBb602cF73E85750b1
	// 0xFa44681FFAF69127A49ceDDBb602cF73E85750b1

	//msg := "testtest"
	msg := GetInput("Input message: ", r)

	msgHash := crypto.Keccak256Hash([]byte(msg))

	signature, _ := crypto.Sign(msgHash.Bytes(), &pvk)

	fmt.Println("Your message signature (without 0x prefix): ")
	fmt.Println(hex.EncodeToString(signature))
	fmt.Println()

	//   e1c90fc6c45ffddfb81d013434afda8a9ce5341d61ad92897e648c915359653b3a9cfae364fe8314db3a12abbc8fabe17bc503753012b0f1b7e224f142c25ebc00
	// 0xe1c90fc6c45ffddfb81d013434afda8a9ce5341d61ad92897e648c915359653b3a9cfae364fe8314db3a12abbc8fabe17bc503753012b0f1b7e224f142c25ebc1b

	recoveredPub, _ := crypto.SigToPub(msgHash.Bytes(), signature)

	recoveredPubBytes := elliptic.Marshal(secp256k1.S256(), recoveredPub.X, recoveredPub.Y)

	fmt.Println("Your recovered public key (with 04 prefix): ")
	fmt.Println(hex.EncodeToString(recoveredPubBytes))
	fmt.Println()

	fmt.Println("Your recovered ETH address: ")
	fmt.Println(crypto.PubkeyToAddress(*recoveredPub).String())
	fmt.Println()

}
