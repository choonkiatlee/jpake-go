package jpake

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"math/big"
)

// EllipticCurve is a general curve which allows other
// elliptic curves to be used with PAKE.
type EllipticCurve interface {
	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
	ScalarBaseMult(k []byte) (*big.Int, *big.Int)
	ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int)
	IsOnCurve(x, y *big.Int) bool
	Params() *elliptic.CurveParams
}

const (
	JPAKESTATE_INITIALISED = iota
	JPAKESTATE_WAITFORROUND1MSG
	JPAKESTATE_WAITFORROUND2MSG
	JPAKESTATE_KEYCOMPUTED
)

type JPake struct {
	// Variables which can be shared
	x1Gx, x1Gy *big.Int
	x2Gx, x2Gy *big.Int
	sessionKey []byte

	// Received Variables / Cached variables
	x2s                  *big.Int
	otherx1Gx, otherx1Gy *big.Int
	otherx2Gx, otherx2Gy *big.Int
	gx, gy               *big.Int // For convenience
	hashFn               HashFnType
	kdf                  KDFType
	curve                EllipticCurve

	// Private Variables
	x1    *big.Int
	x2    *big.Int
	s     *big.Int
	state int
}

type ZKPMsg struct {
	Tx string `json:"tx"`
	Ty string `json:"ty"`
	R  string `json:"r"`
	C  string `json:"c"`
}

type Round1Message struct {
	X1Gx  string `json:"x1Gx"`
	X1Gy  string `json:"x1Gy"`
	X2Gx  string `json:"x2Gx"`
	X2Gy  string `json:"x2Gy"`
	X1ZKP ZKPMsg `json:"x1ZKP"`
	X2ZKP ZKPMsg `json:"x2ZKP"`
}

type Round2Message struct {
	Ax    string `json:"Ax"`
	Ay    string `json:"Ay"`
	XsZKP ZKPMsg `json:"xsZKP"`
}

type CheckSessionKeyMessage struct {
	SessionKey string `json:"SessionKey"`
}

type HashFnType func(string) []byte
type KDFType func([]byte) []byte

func Init(pw string) (*JPake, error) {
	return InitWithCurveAndHashFns(pw, elliptic.P256(), sha256HashFn, hmacsha256KDF)
}

func InitWithCurve(pw string, curve EllipticCurve) (*JPake, error) {
	return InitWithCurveAndHashFns(pw, curve, sha256HashFn, hmacsha256KDF)
}

func InitWithCurveAndHashFns(pw string, curve EllipticCurve, hashFn HashFnType, kdf KDFType) (*JPake, error) {
	jp := new(JPake)
	jp.curve = curve
	jp.hashFn = hashFn
	jp.kdf = kdf
	jp.sessionKey = []byte{} // make sure to invalidate the session key

	jp.gx = curve.Params().Gx
	jp.gy = curve.Params().Gy

	// Compute a simple hash of our secret
	s := (new(big.Int).SetBytes(jp.hashFn(pw)))
	s.Mod(s, curve.Params().N)
	jp.s = s

	// Generate private random variables
	rand1, err := randomNumberInCurveRange(curve)
	if err != nil {
		return jp, err
	}
	rand2, err := randomNumberInCurveRange(curve)
	if err != nil {
		return jp, err
	}
	jp.x1 = rand1
	jp.x2 = rand2

	jp.state = JPAKESTATE_INITIALISED
	return jp, err
}

func (jp *JPake) SetRandomState(x1 *big.Int, x2 *big.Int) {
	// This is a convenience function to let you set the state of the
	// JPAKE object for debugging only
	jp.x1 = x1
	jp.x2 = x2
}

func (jp *JPake) computeZKP(x *big.Int, GeneratorX *big.Int, GeneratorY *big.Int, yx *big.Int, yy *big.Int) (ZKPMsg, error) {
	// Computes a ZKP for x on Generator. We use the Fiat-Shamir heuristic:
	// https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
	// i.e. prove that we know x such that y = x.Generator
	// Note that we differentiate between the point G on the curve, and the
	// Generator used to compute the ZKP

	// 1. Pick a random v \in Z_q* and compute t = vG
	v, err := randomNumberInCurveRange(jp.curve)
	if err != nil {
		return ZKPMsg{}, err
	}

	tx, ty := jp.curve.ScalarMult(GeneratorX, GeneratorY, v.Bytes())

	// 2. Compute c = H(g, y, t) where H() is a cryptographic hash fn
	chal := (asBase64String(GeneratorX) + asBase64String(GeneratorY) +
		asBase64String(tx) + asBase64String(ty) +
		asBase64String(yx) + asBase64String(yy))

	c := (new(big.Int).SetBytes(jp.hashFn(chal)))
	if err != nil {
		return ZKPMsg{}, errors.New("Could not parse from base64")
	}

	// Need to store the result of Mul(c,x) in a new pointer as we need c later,
	// but we don't need to do the same for v because we don't use it afterwards
	rIntermediate := v.Sub(v, new(big.Int).Mul(c, x))
	r := rIntermediate.Mod(rIntermediate, jp.curve.Params().N)

	return ZKPMsg{
		Tx: asBase64String(tx),
		Ty: asBase64String(ty),
		R:  asBase64String(r),
		C:  asBase64String(c),
	}, err
}

func (jp *JPake) checkZKP(msgObj ZKPMsg, Generatorx *big.Int, Generatory *big.Int, yx *big.Int, yy *big.Int) bool {

	tx, err := fromBase64String(msgObj.Tx)
	if err != nil {
		log.Println("Could not convert message from base 64 with error: ", err)
		return false
	}
	ty, err := fromBase64String(msgObj.Ty)
	if err != nil {
		log.Println("Could not convert message from base 64 with error: ", err)
		return false
	}
	r, err := fromBase64String(msgObj.R)
	if err != nil {
		log.Println("Could not convert message from base 64 with error: ", err)
		return false
	}
	c, err := fromBase64String(msgObj.C)
	if err != nil {
		log.Println("Could not convert message from base 64 with error: ", err)
		return false
	}

	chal := (asBase64String(Generatorx) + asBase64String(Generatory) +
		asBase64String(tx) + asBase64String(ty) +
		asBase64String(yx) + asBase64String(yy))
	c = (new(big.Int).SetBytes(jp.hashFn(chal)))

	tmp1x, tmp1y := jp.curve.ScalarMult(Generatorx, Generatory, r.Bytes())
	tmp2x, tmp2y := jp.curve.ScalarMult(yx, yy, c.Bytes())
	Vcheckx, Vchecky := jp.curve.Add(tmp1x, tmp1y, tmp2x, tmp2y)
	return ((Vcheckx.Cmp(tx) == 0) && (Vchecky.Cmp(ty) == 0))
}

func (jp *JPake) GetRound1Message() ([]byte, error) {

	x1Gx, x1Gy := jp.curve.ScalarMult(jp.gx, jp.gy, jp.x1.Bytes())
	jp.x1Gx = x1Gx
	jp.x1Gy = x1Gy

	x2Gx, x2Gy := jp.curve.ScalarMult(jp.gx, jp.gy, jp.x2.Bytes())
	jp.x2Gx = x2Gx
	jp.x2Gy = x2Gy

	x1ZKP, err := jp.computeZKP(jp.x1, jp.gx, jp.gy, jp.x1Gx, jp.x1Gy)
	if err != nil {
		return []byte{}, err
	}
	x2ZKP, err := jp.computeZKP(jp.x2, jp.gx, jp.gy, jp.x2Gx, jp.x2Gy)
	if err != nil {
		return []byte{}, err
	}

	round1Message := Round1Message{
		X1Gx: asBase64String(jp.x1Gx),
		X1Gy: asBase64String(jp.x1Gy),
		X2Gx: asBase64String(jp.x2Gx),
		X2Gy: asBase64String(jp.x2Gy),

		X1ZKP: x1ZKP,
		X2ZKP: x2ZKP,
	}
	return json.Marshal(round1Message)
}

func (jp *JPake) GetRound2Message(jsonMsgfromB []byte) ([]byte, error) {
	var round1MsgFromB Round1Message
	err := json.Unmarshal(jsonMsgfromB, &round1MsgFromB)

	jp.otherx1Gx, err = fromBase64String(round1MsgFromB.X1Gx)
	if err != nil {
		return []byte{}, err
	}
	jp.otherx1Gy, err = fromBase64String(round1MsgFromB.X1Gy)
	if err != nil {
		return []byte{}, err
	}
	jp.otherx2Gx, err = fromBase64String(round1MsgFromB.X2Gx)
	if err != nil {
		return []byte{}, err
	}
	jp.otherx2Gy, err = fromBase64String(round1MsgFromB.X2Gy)
	if err != nil {
		return []byte{}, err
	}

	// validate ZKPs
	x1Proof := jp.checkZKP(round1MsgFromB.X1ZKP, jp.gx, jp.gy, jp.otherx1Gx, jp.otherx1Gy)
	x2Proof := jp.checkZKP(round1MsgFromB.X2ZKP, jp.gx, jp.gy, jp.otherx2Gx, jp.otherx2Gy)

	if !(x1Proof && x2Proof) {
		return []byte{}, errors.New("Could not verify the validity of the received message!")
	}

	// cache for future steps
	jp.x2s = new(big.Int).Mul(jp.x2, jp.s)

	// A = (G1 + G3 + G4) x [x2*s]
	tmp1x, tmp1y := jp.curve.Add(jp.x1Gx, jp.x1Gy, jp.otherx1Gx, jp.otherx1Gy)
	Generatorx, Generatory := jp.curve.Add(tmp1x, tmp1y, jp.otherx2Gx, jp.otherx2Gy)

	// To get Generator x [x2*s], we instead do (Generator x x2) x s.
	// This allows us to get around the 32 byte scalar multiplication limit in the secp256k1 library
	tmp2x, tmp2y := jp.curve.ScalarMult(Generatorx, Generatory, jp.x2.Bytes())
	Ax, Ay := jp.curve.ScalarMult(tmp2x, tmp2y, jp.s.Bytes())

	x2ZKP, err := jp.computeZKP(jp.x2s, Generatorx, Generatory, Ax, Ay)
	if err != nil {
		return []byte{}, err
	}

	round2Msg := Round2Message{
		Ax:    asBase64String(Ax),
		Ay:    asBase64String(Ay),
		XsZKP: x2ZKP,
	}
	return json.Marshal(round2Msg)
}

func (jp *JPake) ComputeSharedKey(jsonMsgfromB []byte) ([]byte, error) {
	var round2MsgFromB Round2Message
	err := json.Unmarshal(jsonMsgfromB, &round2MsgFromB)
	if err != nil {
		return []byte{}, err
	}
	Bx, err := fromBase64String(round2MsgFromB.Ax)
	if err != nil {
		return []byte{}, err
	}
	By, err := fromBase64String(round2MsgFromB.Ay)
	if err != nil {
		return []byte{}, err
	}

	// A = (G1 + G3 + G4)
	tmp1x, tmp1y := jp.curve.Add(jp.x1Gx, jp.x1Gy, jp.x2Gx, jp.x2Gy)
	ZKPGeneratorx, ZKPGeneratory := jp.curve.Add(tmp1x, tmp1y, jp.otherx1Gx, jp.otherx1Gy)
	xsProof := jp.checkZKP(round2MsgFromB.XsZKP, ZKPGeneratorx, ZKPGeneratory, Bx, By)
	if !xsProof {
		return []byte{}, errors.New("Could not verify the validity of the received message!")
	}

	// G4 x [x2*s]
	tmp1x, tmp1y = jp.curve.ScalarMult(jp.otherx2Gx, jp.otherx2Gy, jp.x2.Bytes())
	x2sG4x, x2sG4y := jp.curve.ScalarMult(tmp1x, tmp1y, jp.s.Bytes())

	// B - G4 x [x2 * s]
	negx2sG4x, negx2sG4y := negateCurvePoint(x2sG4x, x2sG4y)
	tmp2x, tmp2y := jp.curve.Add(Bx, By, negx2sG4x, negx2sG4y)

	// Ka = (B - (G4 x [x2*s])) x [x2]
	Kax, _ := jp.curve.ScalarMult(tmp2x, tmp2y, jp.x2.Bytes())
	sharedKey := jp.kdf([]byte(asBase64String(Kax)))
	jp.sessionKey = sharedKey

	return sharedKey, nil
}

func (jp *JPake) SessionKey() ([]byte, error) {
	if len(jp.sessionKey) > 0 {
		return jp.sessionKey, nil
	}
	return []byte{}, errors.New("Shared session key unavailable.")
}

func (jp *JPake) ComputeCheckSessionKeyMsg() ([]byte, error) {
	checkSessionKeyMac := jp.computeSessionKeyMac(
		jp.x1Gx.Bytes(),
		jp.x2Gx.Bytes(),
		jp.otherx1Gx.Bytes(),
		jp.otherx2Gx.Bytes(),
	)

	checkSessionKeyMsg := CheckSessionKeyMessage{
		SessionKey: base64.StdEncoding.EncodeToString(checkSessionKeyMac),
	}

	json, err := json.Marshal(checkSessionKeyMsg)
	if err != nil {
		return []byte{}, err
	}

	return json, nil
}

func (jp *JPake) CheckReceivedSessionKeyMsg(jsonMsgfromB []byte) bool {
	var sessionKeyMsg CheckSessionKeyMessage
	err := json.Unmarshal(jsonMsgfromB, &sessionKeyMsg)
	if err != nil {
		log.Println("Could not unmarshall check session key msg")
		return false
	}
	receivedSessionKeyMac, err := base64.StdEncoding.DecodeString(sessionKeyMsg.SessionKey)
	if err != nil {
		log.Println("Could not unmarshall check session key msg")
		return false
	}
	toCheckAgainst := jp.computeSessionKeyMac(
		jp.otherx1Gx.Bytes(),
		jp.otherx2Gx.Bytes(),
		jp.x1Gx.Bytes(),
		jp.x2Gx.Bytes(),
	)

	return bytes.Compare(receivedSessionKeyMac, toCheckAgainst) == 0
}

func (jp *JPake) computeSessionKeyMac(
	x1G []byte,
	x2G []byte,
	otherx1G []byte,
	otherx2G []byte,
) []byte {
	kprime := jp.kdf(append(jp.sessionKey, []byte("KC_1_U")...))

	slices := [][]byte{
		[]byte("KC_1_U"),
		[]byte("Alice"),
		[]byte("Bob"),
		x1G,
		x2G,
		otherx1G,
		otherx2G,
	}
	macTagAlice := hmacsha256(
		kprime,
		concatByteSlices(slices),
	)
	return macTagAlice
}

// Utilities
func asBase64String(x *big.Int) string {
	return base64.StdEncoding.EncodeToString(x.Bytes())
}

func fromBase64String(input string) (*big.Int, error) {
	data, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}

	res := new(big.Int)
	res.SetBytes(data)
	return res, err
}

func concatByteSlices(slices [][]byte) []byte {
	var totalLen int = 0
	for _, s := range slices {
		totalLen += len(s)
	}
	tmp := make([]byte, totalLen)
	var i int
	for _, s := range slices {
		i += copy(tmp[i:], s)
	}
	return tmp
}

// Some curve utilities
func randomNumberInCurveRange(curve EllipticCurve) (*big.Int, error) {
	CurveNMinus1 := new(big.Int)
	CurveNMinus1 = CurveNMinus1.Sub(curve.Params().N, big.NewInt(1))
	rand1, err := rand.Int(rand.Reader, CurveNMinus1)
	if err != nil {
		return &big.Int{}, err
	}
	return rand1, err
}

func negateCurvePoint(x *big.Int, y *big.Int) (*big.Int, *big.Int) {
	return x, new(big.Int).Neg(y)
}

// Example hash function.
func sha256HashFn(s string) []byte {
	hash := sha256.Sum256([]byte(s))
	return hash[:]
}

func hmacsha256KDF(input []byte) []byte {
	return hmacsha256(input, []byte("kdfsecret")) // use a known key for determinism
}

func hmacsha256(input []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	return mac.Sum(nil)
}
