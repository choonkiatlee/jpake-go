# JPAKE 

This library allows 2 parties to generate a mutual secret key using a weak key that is known to each other beforehand.
This provides a simple API over an implementation of Password Authenticated Key Exchange by Juggling (J-PAKE) based on elliptic curves (currently secp2561k). 

This protocol is derived from the [J-PAKE paper](https://eprint.iacr.org/2010/190.pdf) and [relevant RFC](https://tools.ietf.org/html/rfc8236).
This is a companion project to the [javascript version](https://github.com/choonkiatlee/jpake-js), and all messages are interchangeable between the 2 libraries. 


# Install
```go get github.com/choonkiatlee/jpake-go```

# Quick Start
```go
func main() {

	// initialise a curve to use.
	secret := "weaksecret"

	jpA, err := jpake.Init(secret)
	panicOnErr(err)
	jpB, err := jpake.Init(secret)
	panicOnErr(err)

	msgA1, err := jpA.GetRound1Message()
	panicOnErr(err)
	msgB1, err := jpB.GetRound1Message()
	panicOnErr(err)

	msgA2, err := jpA.GetRound2Message(msgB1)
	panicOnErr(err)
	msgB2, err := jpB.GetRound2Message(msgA1)
	panicOnErr(err)

	sharedKeyA, err := jpA.ComputeSharedKey(msgB2)
	panicOnErr(err)
	sharedKeyB, err := jpB.ComputeSharedKey(msgA2)
	panicOnErr(err)

	fmt.Println("\nShared Keys Generated: ")
	fmt.Println("\nAlice key: ", sharedKeyA)
	fmt.Println("Bob key: ", sharedKeyB)
}

func panicOnErr(err){
    if err != nil {
        panic(err)
    }
}
```

# JPAKE theory

* Explanation to come

# Implementation Notes:

- This currently uses Javascript BigInts.