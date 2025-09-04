package keyderivation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// Reed-Solomon encoding for Ardor addresses
var (
	// Reed-Solomon parameters
	gexp_rs = []int{1, 2, 4, 8, 16, 5, 10, 20, 13, 26, 17, 7, 14, 28, 29, 31, 27, 19, 3, 6, 12, 24, 21, 15, 30, 25, 23, 11, 22, 9, 18, 1}
	glog_rs = []int{0, 0, 1, 18, 2, 5, 19, 11, 3, 29, 6, 27, 20, 8, 12, 23, 4, 10, 30, 17, 7, 22, 28, 26, 21, 25, 9, 16, 13, 14, 24, 15}
	cwmap_rs = []int{3, 2, 1, 0, 7, 6, 5, 4, 13, 14, 15, 16, 12, 8, 9, 10, 11}
	alphabet_rs = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
)

// gmult_rs performs Galois field multiplication
func gmult_rs(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	idx := (glog_rs[a] + glog_rs[b]) % 31
	return gexp_rs[idx]
}

// EncodeReedSolomon encodes account ID to Reed-Solomon format
func EncodeReedSolomon(accountID string) (string, error) {
	codeword := make([]int, 17)
	for i := range codeword {
		codeword[i] = 1
	}
	
	// Convert account ID to base 32
	if !fromAccountID(accountID, codeword) {
		return "", fmt.Errorf("invalid account ID: %s", accountID)
	}
	
	// Encode with Reed-Solomon
	encode_rs(codeword)
	
	// Convert to string
	out := "ARDOR-"
	for i := 0; i < 17; i++ {
		out += string(alphabet_rs[codeword[cwmap_rs[i]]])
		if (i&3) == 3 && i < 13 {
			out += "-"
		}
	}
	
	return out, nil
}

// fromAccountID converts account ID string to base 32 codeword
func fromAccountID(accStr string, codeword []int) bool {
	if len(accStr) == 0 {
		return false
	}
	
	// Handle "1" prefix for 20-digit account IDs
	if len(accStr) == 20 && accStr[0] != '1' {
		return false
	}
	
	// Convert string to digit array
	inp := make([]int, len(accStr))
	for i, c := range accStr {
		if c < '0' || c > '9' {
			return false
		}
		inp[i] = int(c - '0')
	}
	
	// Base 10 to base 32 conversion
	out := make([]int, 13)
	pos := 0
	length := len(inp)
	
	for length > 0 {
		divide := 0
		newlen := 0
		
		for i := 0; i < length; i++ {
			divide = divide*10 + inp[i]
			if divide >= 32 {
				inp[newlen] = divide >> 5
				newlen++
				divide &= 31
			} else if newlen > 0 {
				inp[newlen] = 0
				newlen++
			}
		}
		
		length = newlen
		out[pos] = divide
		pos++
	}
	
	// Copy to codeword in reverse, pad with 0's
	for i := 0; i < 13; i++ {
		pos--
		if pos >= 0 {
			codeword[i] = out[i]
		} else {
			codeword[i] = 0
		}
	}
	
	return true
}

// encode_rs performs Reed-Solomon encoding
func encode_rs(codeword []int) {
	p := []int{0, 0, 0, 0}
	
	for i := 12; i >= 0; i-- {
		fb := codeword[i] ^ p[3]
		p[3] = p[2] ^ gmult_rs(30, fb)
		p[2] = p[1] ^ gmult_rs(6, fb)
		p[1] = p[0] ^ gmult_rs(9, fb)
		p[0] = gmult_rs(17, fb)
	}
	
	codeword[13] = p[0]
	codeword[14] = p[1]
	codeword[15] = p[2]
	codeword[16] = p[3]
}

// GetPrivateKeyHex returns the complete private key as hex string
func (n *Bip32Node) GetPrivateKeyHex() string {
	combined := make([]byte, 64)
	copy(combined[:32], n.PrivateKeyLeft)
	copy(combined[32:], n.PrivateKeyRight)
	return hex.EncodeToString(combined)
}

// GetAccountID returns the account ID from a public key
func GetAccountID(publicKey []byte) string {
	// Hash the public key with SHA-256
	hash := sha256.Sum256(publicKey)
	
	// Take first 8 bytes and convert to big integer
	accountBytes := hash[:8]
	
	// Convert to big integer (big-endian, like JavaScript byteArrayToBigInteger)
	accountID := new(big.Int)
	for i := len(accountBytes) - 1; i >= 0; i-- {
		accountID = accountID.Mul(accountID, big.NewInt(256))
		accountID = accountID.Add(accountID, big.NewInt(int64(accountBytes[i])))
	}
	
	return accountID.String()
}

// GetArdorAddress converts a public key to Ardor address format
func GetArdorAddress(publicKey []byte) (string, error) {
	accountID := GetAccountID(publicKey)
	return EncodeReedSolomon(accountID)
}

// GetPublicKeyFromPrivateKey generates a public key from private key using Curve25519
func GetPublicKeyFromPrivateKey(privateKey []byte) []byte {
	// Use curve25519 key generation like JavaScript curve25519.keygen(privateKey).p
	publicKeyPoint := scalarMultiplicationCurve25519Base(privateKey)
	return publicKeyPoint.EncodeWithMask(true) // Ed25519 Y coordinate only (no mask)
}

// GetPrivateKeyAndAddress derives both private key and Ardor address from mnemonic and path
func GetPrivateKeyAndAddress(mnemonic, path string) (string, string, error) {
	// Derive the key
	node, err := DeriveMnemonic(path, mnemonic)
	if err != nil {
		return "", "", err
	}
	
	// Get private key (left part only, as used in JavaScript)
	privateKey := hex.EncodeToString(node.PrivateKeyLeft)
	
	// Use the Curve25519 public key directly for address generation
	address, err := GetArdorAddress(node.PublicKey)
	if err != nil {
		return "", "", err
	}
	
	return privateKey, address, nil
}