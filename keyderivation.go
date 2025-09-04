package keyderivation

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	PassphrasePrefix = "mnemonic"
	RootChainCode    = "ed25519 seed"
)

var (
	TwoPower31  = big.NewInt(2147483648) // 2^31
	TwoPower32  = big.NewInt(4294967296) // 2^32
	TwoPower256 = new(big.Int)
	Eight       = big.NewInt(8)
	
	// Ed25519 constants matching JavaScript noble-ed25519
	Ed25519P          = new(big.Int) // 2^255 - 19
	Ed25519PrimeOrder = new(big.Int) // 2^252 + 27742317777372353535851937790883648493
	Ed25519D          = new(big.Int) // -121665 * inversion(121666)
	Ed25519I          = new(big.Int) // powMod(2, (P-1)/4, P)
)

func init() {
	// 2^256
	TwoPower256.SetString("115792089237316195423570985008687907853269984665640564039457584007913129639936", 10)
	
	// Ed25519 constants
	Ed25519P.SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10) // 2^255 - 19
	Ed25519PrimeOrder.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10) // 2^252 + 27742317777372353535851937790883648493
	
	// d = -121665 * inversion(121666) mod p
	inv121666 := modInverse(big.NewInt(121666), Ed25519P)
	Ed25519D.Mul(big.NewInt(-121665), inv121666)
	Ed25519D.Mod(Ed25519D, Ed25519P)
	
	// I = powMod(2, (P-1)/4, P)
	exp := new(big.Int).Sub(Ed25519P, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	Ed25519I.Exp(big.NewInt(2), exp, Ed25519P)
}

// Ed25519Point represents a point on the Ed25519 curve
type Ed25519Point struct {
	X *big.Int
	Y *big.Int
}

// NewEd25519Point creates a new Ed25519 point
func NewEd25519Point(x, y *big.Int) *Ed25519Point {
	return &Ed25519Point{
		X: new(big.Int).Set(x),
		Y: new(big.Int).Set(y),
	}
}

// Ed25519BasePoint returns the base point for Ed25519
func Ed25519BasePoint() *Ed25519Point {
	// Base point coordinates from JavaScript noble-ed25519
	x := new(big.Int)
	y := new(big.Int)
	x.SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
	y.SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)
	return NewEd25519Point(x, y)
}

// modInverse computes the modular inverse
func modInverse(a, m *big.Int) *big.Int {
	result := new(big.Int)
	result.ModInverse(a, m)
	return result
}

// mod performs modular arithmetic, ensuring positive result
func mod(a, m *big.Int) *big.Int {
	result := new(big.Int).Mod(a, m)
	if result.Sign() < 0 {
		result.Add(result, m)
	}
	return result
}

// Add performs point addition on Ed25519
func (p *Ed25519Point) Add(q *Ed25519Point) *Ed25519Point {
	// Edwards curve addition formula
	// x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
	// y3 = (y1*y2 - A*x1*x2) / (1 - d*x1*x2*y1*y2)
	// For Ed25519, A = -1
	
	x1y2 := new(big.Int).Mul(p.X, q.Y)
	y1x2 := new(big.Int).Mul(p.Y, q.X)
	y1y2 := new(big.Int).Mul(p.Y, q.Y)
	x1x2 := new(big.Int).Mul(p.X, q.X)
	
	dx1x2y1y2 := new(big.Int).Mul(Ed25519D, x1x2)
	dx1x2y1y2.Mul(dx1x2y1y2, y1y2)
	
	// x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
	x3_num := new(big.Int).Add(x1y2, y1x2)
	x3_den := new(big.Int).Add(big.NewInt(1), dx1x2y1y2)
	x3_den_inv := modInverse(x3_den, Ed25519P)
	x3 := new(big.Int).Mul(x3_num, x3_den_inv)
	x3 = mod(x3, Ed25519P)
	
	// y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2) [A = -1, so -A*x1*x2 = +x1*x2]
	y3_num := new(big.Int).Add(y1y2, x1x2)
	y3_den := new(big.Int).Sub(big.NewInt(1), dx1x2y1y2)
	y3_den_inv := modInverse(y3_den, Ed25519P)
	y3 := new(big.Int).Mul(y3_num, y3_den_inv)
	y3 = mod(y3, Ed25519P)
	
	return NewEd25519Point(x3, y3)
}

// Multiply performs scalar multiplication using double-and-add
func (p *Ed25519Point) Multiply(n *big.Int) *Ed25519Point {
	// Identity point (0, 1)
	q := NewEd25519Point(big.NewInt(0), big.NewInt(1))
	db := NewEd25519Point(p.X, p.Y)
	
	nCopy := new(big.Int).Set(n)
	for nCopy.Sign() > 0 {
		if nCopy.Bit(0) == 1 { // if n & 1 == 1
			q = q.Add(db)
		}
		nCopy.Rsh(nCopy, 1) // n >>= 1
		db = db.Add(db)     // db = db + db
	}
	
	return q
}

// Encode encodes the point to bytes (Y coordinate with X sign bit)
func (p *Ed25519Point) Encode() []byte {
	return p.EncodeWithMask(false)
}

// EncodeWithMask encodes the point, optionally including the X parity bit
func (p *Ed25519Point) EncodeWithMask(noMask bool) []byte {
	// Convert Y to little-endian bytes
	yBytes := make([]byte, 32)
	yBig := new(big.Int).Set(p.Y)
	
	// Convert to little-endian
	for i := 0; i < 32 && yBig.Sign() > 0; i++ {
		yBytes[i] = byte(yBig.Uint64() & 0xff)
		yBig.Rsh(yBig, 8)
	}
	
	// Set the sign bit based on X coordinate parity (unless noMask is true)
	if !noMask && p.X.Bit(0) == 1 {
		yBytes[31] |= 0x80
	}
	
	return yBytes
}

// Bip32Node represents a BIP32 hierarchical deterministic key node
type Bip32Node struct {
	PrivateKeyLeft   []byte
	PrivateKeyRight  []byte
	MasterPublicKey  []byte
	ChainCode        []byte
	PublicKey        []byte
}

// GetPrivateKeyLeft returns the left part of the private key
func (n *Bip32Node) GetPrivateKeyLeft() []byte {
	return n.PrivateKeyLeft
}

// GetPrivateKeyRight returns the right part of the private key
func (n *Bip32Node) GetPrivateKeyRight() []byte {
	return n.PrivateKeyRight
}

// GetMasterPublicKey returns the master public key
func (n *Bip32Node) GetMasterPublicKey() []byte {
	return n.MasterPublicKey
}

// GetChainCode returns the chain code
func (n *Bip32Node) GetChainCode() []byte {
	return n.ChainCode
}

// GetPublicKey returns the public key
func (n *Bip32Node) GetPublicKey() []byte {
	return n.PublicKey
}

// String returns a string representation of the node
func (n *Bip32Node) String() string {
	return fmt.Sprintf("Bip32Node{privateKeyLeft=%x, privateKeyRight=%x, masterPublicKey=%x, chainCode=%x, publicKey=%x}",
		n.PrivateKeyLeft, n.PrivateKeyRight, n.MasterPublicKey, n.ChainCode, n.PublicKey)
}

// MnemonicToSeed converts a mnemonic to a seed using PBKDF2
func MnemonicToSeed(mnemonic string) []byte {
	return MnemonicAndPassphraseToSeed(mnemonic, "")
}

// MnemonicAndPassphraseToSeed converts a mnemonic and passphrase to a seed
func MnemonicAndPassphraseToSeed(mnemonic, passphrase string) []byte {
	return MnemonicAndSaltToSeed(mnemonic, PassphrasePrefix+passphrase)
}

// MnemonicAndSaltToSeed converts a mnemonic and salt to a seed using PBKDF2
func MnemonicAndSaltToSeed(mnemonic, salt string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte(salt), 2048, 64, sha512.New)
}

// clamp clamps the private key according to Ed25519 spec
func clamp(k []byte) {
	k[31] &= 0x7F
	k[31] |= 0x40
	k[0] &= 0xF8
}

// switchEndian reverses the byte order
func switchEndian(b []byte) []byte {
	result := make([]byte, len(b))
	copy(result, b)
	for i := 0; i < len(result)/2; i++ {
		result[i], result[len(result)-i-1] = result[len(result)-i-1], result[i]
	}
	return result
}

// bigIntToByteArray converts a big integer to a byte array with specified length
func bigIntToByteArray(num *big.Int, bytesLength int) []byte {
	str := fmt.Sprintf("%0*x", bytesLength*2, num)
	if len(str) > bytesLength*2 {
		str = str[len(str)-bytesLength*2:]
	}
	bytes, _ := hex.DecodeString(str)
	return switchEndian(bytes)
}

// byteArrayToBigInt converts a byte array to a big integer
func byteArrayToBigInt(b []byte) *big.Int {
	reversed := switchEndian(b)
	result := new(big.Int)
	result.SetBytes(reversed)
	return result
}

// getSha256Commitment computes HMAC-SHA256
func getSha256Commitment(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// getSha512Commitment computes HMAC-SHA512
func getSha512Commitment(message, key []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// scalarMultiplicationCurve25519Base performs scalar multiplication with the base point
func scalarMultiplicationCurve25519Base(k []byte) *Ed25519Point {
	// Convert bytes to big integer matching JavaScript byteArrayToBigint
	// JavaScript: BigInt("0x" + converters.byteArrayToHexString(switchEndian(b.slice())))
	// This means: reverse bytes, then treat as big-endian hex
	reversed := switchEndian(k)
	n := new(big.Int)
	n.SetBytes(reversed)
	
	// Perform scalar multiplication with base point
	basePoint := Ed25519BasePoint()
	return basePoint.Multiply(n)
}

// DeriveMnemonic derives a key from a mnemonic and BIP32 path
func DeriveMnemonic(path, mnemonic string) (*Bip32Node, error) {
	seed := MnemonicToSeed(mnemonic)
	return DeriveSeed(path, seed)
}

// DeriveSeed derives a key from a seed and BIP32 path
func DeriveSeed(path string, seed []byte) (*Bip32Node, error) {
	node, err := GetRootNode(seed)
	if err != nil {
		return nil, err
	}

	pathSplit := strings.Split(path, "/")
	for _, pathComponent := range pathSplit {
		if strings.ToLower(pathComponent) == "m" {
			continue
		}

		var childIndex *big.Int
		if strings.HasSuffix(pathComponent, "'") {
			indexStr := pathComponent[:len(pathComponent)-1]
			index, err := strconv.ParseInt(indexStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid path component: %s", pathComponent)
			}
			childIndex = new(big.Int).Add(big.NewInt(index), TwoPower31)
		} else {
			index, err := strconv.ParseInt(pathComponent, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid path component: %s", pathComponent)
			}
			childIndex = big.NewInt(index)
		}

		node, err = DeriveChildPrivateKey(node, childIndex)
		if err != nil {
			return nil, err
		}
	}

	return node, nil
}

// GetRootNode creates the root node from a seed
func GetRootNode(seed []byte) (*Bip32Node, error) {
	rootChainCode := []byte(RootChainCode)
	return getRootNodeImpl(seed, rootChainCode)
}

// getRootNodeImpl implements the root node creation
func getRootNodeImpl(seed, rootChainCode []byte) (*Bip32Node, error) {
	// Root chain code
	message := append([]byte{0x01}, seed...)
	chainCode := getSha256Commitment(message, rootChainCode)

	// Calculate private key left and right
	rootCommitment := getSha512Commitment(seed, rootChainCode)
	keyLeft := make([]byte, 32)
	keyRight := make([]byte, 32)
	copy(keyLeft, rootCommitment[:32])
	copy(keyRight, rootCommitment[32:64])

	for (keyLeft[31] & 0x20) != 0 {
		rootCommitment = getSha512Commitment(rootCommitment, rootChainCode)
		copy(keyLeft, rootCommitment[:32])
		copy(keyRight, rootCommitment[32:64])
	}
	
	clamp(keyLeft)

	// Root public key
	publicKeyPoint := scalarMultiplicationCurve25519Base(keyLeft)
	publicKey := publicKeyPoint.Encode()                // Ed25519 with X parity bit
	publicKeyY := publicKeyPoint.EncodeWithMask(true)   // Ed25519 Y coordinate only (no mask)
	
	// Convert ed25519 Y coordinate to curve25519 for compatibility
	curve25519PublicKey := ed25519ToCurve25519(publicKeyY)

	return &Bip32Node{
		PrivateKeyLeft:  keyLeft,
		PrivateKeyRight: keyRight,
		MasterPublicKey: publicKey,
		ChainCode:       chainCode,
		PublicKey:       curve25519PublicKey,
	}, nil
}

// ed25519ToCurve25519 converts an Ed25519 public key to Curve25519
// This exactly matches the JavaScript CurveConversion.ed25519ToCurve25519 implementation
func ed25519ToCurve25519(ed25519Key []byte) []byte {
	const size = 32
	
	if len(ed25519Key) != 32 {
		return ed25519Key // fallback
	}
	
	// Create working arrays - matching JavaScript implementation
	edwardY := make([]byte, size)
	copy(edwardY, ed25519Key)
	
	yplus := make([]byte, size)
	yminus := make([]byte, size)
	montgomeryX := make([]byte, size)
	
	// Step 1: yplus = 1 - edwardY (sub function in JS)
	sub25519(yplus, edwardY)
	
	// Step 2: yminus = 1 / yplus (invDistinct function in JS)
	inv25519(yminus, yplus)
	
	// Step 3: yplus = 1 + edwardY (add function in JS)  
	add25519(yplus, edwardY)
	
	// Step 4: montgomeryX = yplus * yminus (mulDistinct function in JS)
	mul25519(montgomeryX, yplus, yminus)
	
	// Step 5: normalize the result
	normalize25519(montgomeryX)
	
	return montgomeryX
}

// Field arithmetic for Curve25519 (p = 2^255 - 19)

func one25519() []byte {
	one := make([]byte, 32)
	one[0] = 1
	return one
}

func normalize25519(x []byte) {
	// Reduce using 2^255 = 19 mod p
	c := int32(x[31]>>7) * 19
	x[31] &= 0x7f

	for i := 0; i < 32; i++ {
		c += int32(x[i])
		x[i] = byte(c & 0xff)
		c >>= 8
	}

	// The number is now less than 2^255 + 18, and therefore less than 2p.
	// Try subtracting p, and conditionally load the subtracted value if underflow did not occur.
	c = 19
	minusp := make([]byte, 32)
	
	for i := 0; i < 31; i++ {
		c += int32(x[i])
		minusp[i] = byte(c & 0xff)
		c >>= 8
	}

	c += int32(x[31]) - 0x80
	minusp[31] = byte(c & 0xff)

	// Load x-p if no underflow
	mask := byte(-((c >> 15) & 1))
	for i := 0; i < 32; i++ {
		x[i] = minusp[i] ^ (mask & (x[i] ^ minusp[i]))
	}
}

// add25519 implements the JavaScript add function: r = ONE + b
func add25519(r, b []byte) {
	one := one25519()
	
	// Add
	c := int32(0)
	for i := 0; i < 32; i++ {
		c >>= 8
		c += int32(one[i]) + int32(b[i])
		r[i] = byte(c & 0xff)
	}

	// Reduce with 2^255 = 19 mod p
	r[31] &= 127
	c = (c >> 7) * 19

	for i := 0; i < 32; i++ {
		c += int32(r[i])
		r[i] = byte(c & 0xff)
		c >>= 8
	}
}

// sub25519 implements the JavaScript sub function: r = ONE - b
func sub25519(r, b []byte) {
	one := one25519()
	
	// Calculate ONE + 2p - b, to avoid underflow
	c := int32(218)
	for i := 0; i < 31; i++ {
		c += 65280 + int32(one[i]) - int32(b[i])
		r[i] = byte(c & 0xff)
		c >>= 8
	}

	c += int32(one[31]) - int32(b[31])
	r[31] = byte(c & 0x7f)
	c = (c >> 7) * 19

	for i := 0; i < 32; i++ {
		c += int32(r[i])
		r[i] = byte(c & 0xff)
		c >>= 8
	}
}

func mul25519(r, a, b []byte) {
	c := int64(0)
	for i := 0; i < 32; i++ {
		c >>= 8
		for j := 0; j <= i; j++ {
			c += int64(a[j]&0xff) * int64(b[i-j]&0xff)
		}

		for j := i + 1; j < 32; j++ {
			c += int64(a[j]&0xff) * int64(b[i+32-j]&0xff) * 38
		}

		r[i] = byte(c & 0xff)
	}

	r[31] &= 127
	c = (c >> 7) * 19

	for i := 0; i < 32; i++ {
		c += int64(r[i])
		r[i] = byte(c & 0xff)
		c >>= 8
	}
}

func inv25519(r, x []byte) {
	s := make([]byte, 32)

	// Fermat's little theorem: x^(p-2) = x^(-1) mod p
	// p-2 = 2^255-21 for Curve25519
	
	// 1 1
	mul25519(s, x, x)
	mul25519(r, s, x)

	// 1 x 248
	for i := 0; i < 248; i++ {
		mul25519(s, r, r)
		mul25519(r, s, x)
	}

	// 0
	mul25519(s, r, r)

	// 1
	mul25519(r, s, s)
	mul25519(s, r, x)

	// 0
	mul25519(r, s, s)

	// 1
	mul25519(s, r, r)
	mul25519(r, s, x)

	// 1
	mul25519(s, r, r)
	mul25519(r, s, x)
}

// DeriveChildPrivateKey derives a child private key from a parent node
func DeriveChildPrivateKey(node *Bip32Node, childIndex *big.Int) (*Bip32Node, error) {
	if node == nil {
		return nil, errors.New("node not specified")
	}
	if childIndex.Cmp(big.NewInt(0)) < 0 || childIndex.Cmp(TwoPower32) >= 0 {
		return nil, fmt.Errorf("path component not in range: %s", childIndex.String())
	}

	childIndexBytes := bigIntToByteArray(childIndex, 4)

	var childKeyCommitment []byte
	var bytes []byte

	if childIndex.Cmp(TwoPower31) < 0 {
		// Regular child
		bytes = append([]byte{0x02}, node.GetMasterPublicKey()...)
		bytes = append(bytes, childIndexBytes...)
		childKeyCommitment = getSha512Commitment(bytes, node.GetChainCode())
		bytes[0] = 0x03
	} else {
		// Hardened child
		bytes = append([]byte{0x00}, node.GetPrivateKeyLeft()...)
		bytes = append(bytes, node.GetPrivateKeyRight()...)
		bytes = append(bytes, childIndexBytes...)
		childKeyCommitment = getSha512Commitment(bytes, node.GetChainCode())
		bytes[0] = 0x01
	}

	childKeyCommitmentLeft := childKeyCommitment[:28]
	childKeyCommitmentRight := childKeyCommitment[32:64]
	chainCodeCommitment := getSha512Commitment(bytes, node.GetChainCode())
	chainCode := chainCodeCommitment[32:64]

	// Compute private key left
	childKeyCommitmentLeftNum := byteArrayToBigInt(childKeyCommitmentLeft)
	parentPrivateKeyLeftNum := byteArrayToBigInt(node.GetPrivateKeyLeft())
	privateKeyLeftNum := new(big.Int).Add(
		new(big.Int).Mul(childKeyCommitmentLeftNum, Eight),
		parentPrivateKeyLeftNum,
	)

	// Check for identity point (theoretical case)
	// Using the Ed25519 prime order: 2^252 + 27742317777372353535851937790883648493
	primeOrder := new(big.Int)
	primeOrder.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	if new(big.Int).Mod(privateKeyLeftNum, primeOrder).Cmp(big.NewInt(0)) == 0 {
		return nil, errors.New("identity point was derived")
	}

	keyLeft := bigIntToByteArray(privateKeyLeftNum, 32)

	// Compute private key right
	childKeyCommitmentRightNum := byteArrayToBigInt(childKeyCommitmentRight)
	parentPrivateKeyRightNum := byteArrayToBigInt(node.GetPrivateKeyRight())
	privateKeyRightNum := new(big.Int).Mod(
		new(big.Int).Add(childKeyCommitmentRightNum, parentPrivateKeyRightNum),
		TwoPower256,
	)
	keyRight := bigIntToByteArray(privateKeyRightNum, 32)

	// Compute public key
	publicKeyPoint := scalarMultiplicationCurve25519Base(keyLeft)
	publicKey := publicKeyPoint.Encode()                // Ed25519 with X parity bit
	publicKeyY := publicKeyPoint.EncodeWithMask(true)   // Ed25519 Y coordinate only (no mask)
	
	// Convert ed25519 Y coordinate to curve25519 for compatibility
	curve25519PublicKey := ed25519ToCurve25519(publicKeyY)

	return &Bip32Node{
		PrivateKeyLeft:  keyLeft,
		PrivateKeyRight: keyRight,
		MasterPublicKey: publicKey,
		ChainCode:       chainCode,
		PublicKey:       curve25519PublicKey,
	}, nil
}