package keyderivation

import (
	"encoding/hex"
	"testing"
)

func TestEd25519BasePoint(t *testing.T) {
	// Test our base point encoding against JavaScript
	basePoint := Ed25519BasePoint()
	encoded := basePoint.Encode()
	
	// JavaScript base point should encode to: 5866666666666666666666666666666666666666666666666666666666666666
	expectedHex := "5866666666666666666666666666666666666666666666666666666666666666"
	actualHex := hex.EncodeToString(encoded)
	
	t.Logf("Expected base point: %s", expectedHex)
	t.Logf("Actual base point:   %s", actualHex)
	
	if actualHex != expectedHex {
		t.Errorf("Base point encoding mismatch")
	}
}

func TestScalarMultiplication(t *testing.T) {
	// Test scalar multiplication with 8
	// JavaScript: let eight = BigInt(8); let eightBytes = converters.hexStringToByteArray(converters.bigIntToHexString(eight));
	// Expected result: b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321
	
	eightBytes := []byte{8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	point := scalarMultiplicationCurve25519Base(eightBytes)
	encoded := point.Encode()
	
	expectedHex := "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321"
	actualHex := hex.EncodeToString(encoded)
	
	t.Logf("Expected 8*G: %s", expectedHex)
	t.Logf("Actual 8*G:   %s", actualHex)
	
	if actualHex != expectedHex {
		t.Errorf("Scalar multiplication mismatch")
	}
}