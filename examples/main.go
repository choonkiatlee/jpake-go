package main

import (
	"crypto/elliptic"
	"fmt"

	"github.com/choonkiatlee/jpake-go"
	// "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func main() {

	// curve := secp256k1.S256()
	curve := elliptic.P256()
	secret := "weaksecret"

	jpA, err := jpake.InitWithCurve(secret, curve)
	if err != nil {
		panic(err)
	}
	jpB, err := jpake.InitWithCurve(secret, curve)
	if err != nil {
		panic(err)
	}

	msgA1, err := jpA.GetRound1Message()
	if err != nil {
		panic(err)
	}
	msgB1, err := jpB.GetRound1Message()
	if err != nil {
		panic(err)
	}

	fmt.Println("Shared Password: ", secret)
	fmt.Println("\nRound1 Message Exchange")
	fmt.Println("\n===Alice Message To Bob===")
	fmt.Println(string(msgA1))
	fmt.Println("\n===Bob Message To Alice===")
	fmt.Println(string(msgB1))

	msgA2, err := jpA.GetRound2Message(msgB1)
	if err != nil {
		panic(err)
	}
	msgB2, err := jpB.GetRound2Message(msgA1)
	if err != nil {
		panic(err)
	}

	fmt.Println("\nRound2 Message Exchange")
	fmt.Println("\n===Alice Message To Bob===")
	fmt.Println(string(msgA2))
	fmt.Println("\n===Bob Message To Alice===")
	fmt.Println(string(msgB2))

	sharedKeyA, err := jpA.ComputeSharedKey(msgB2)
	if err != nil {
		panic(err)
	}
	sharedKeyB, err := jpB.ComputeSharedKey(msgA2)
	if err != nil {
		panic(err)
	}

	fmt.Println("\nShared Keys Generated: ")
	fmt.Println("\nAlice key: ", sharedKeyA)
	fmt.Println("Bob key: ", sharedKeyB)

	checkKeyMsgA, err := jpA.ComputeCheckSessionKeyMsg()
	if err != nil {
		panic(err)
	}
	checkKeyMsgB, err := jpB.ComputeCheckSessionKeyMsg()
	if err != nil {
		panic(err)
	}

	validA := jpA.CheckReceivedSessionKeyMsg(checkKeyMsgB)
	validB := jpB.CheckReceivedSessionKeyMsg(checkKeyMsgA)

	fmt.Println("\nChecking Generated Shared Keys...")
	fmt.Println("\nAlice check: ", validA)
	fmt.Println("Bob check: ", validB)

}
