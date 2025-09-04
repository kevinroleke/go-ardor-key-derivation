package keyderivation

import (
	"strings"
	"testing"
)

func TestArdorAddressGeneration(t *testing.T) {
	// Test the main user-provided test case
	mnemonic := "side vast trash guard circle voyage undo behave sustain punch pave club admit fox step letter awake item"
	path := "m/44'/16754'/0'/0'/2"
	expectedPrivateKey := "90faba24732286fa508cce36f286372c026008a0bb6fad024e179f4f92563541"
	expectedAddress := "ARDOR-6F4J-Y4GH-SVZK-9RMRL"
	
	privateKey, address, err := GetPrivateKeyAndAddress(mnemonic, path)
	if err != nil {
		t.Fatalf("Failed to derive key and address: %v", err)
	}
	
	t.Logf("Mnemonic: %s", mnemonic)
	t.Logf("Path: %s", path)
	t.Logf("Private Key: %s", privateKey)
	t.Logf("Ardor Address: %s", address)
	
	if privateKey != expectedPrivateKey {
		t.Errorf("Private key mismatch. Expected: %s, Got: %s", expectedPrivateKey, privateKey)
	}
	
	if address != expectedAddress {
		t.Errorf("Address mismatch. Expected: %s, Got: %s", expectedAddress, address)
	}
}

func TestMultipleDerivations(t *testing.T) {
	// Test multiple derivation paths to ensure the implementation is robust
	mnemonic := "side vast trash guard circle voyage undo behave sustain punch pave club admit fox step letter awake item"
	testPaths := []string{
		"m/44'/16754'/0'/0'/0",
		"m/44'/16754'/0'/0'/1", 
		"m/44'/16754'/0'/0'/2",
		"m/44'/16754'/0'/0'/3",
		"m/44'/16754'/0'/0'/4",
		"m/44'/16754'/0'/0'/5",
	}
	
	for _, path := range testPaths {
		privateKey, address, err := GetPrivateKeyAndAddress(mnemonic, path)
		if err != nil {
			t.Errorf("Failed to derive path %s: %v", path, err)
			continue
		}
		
		// Validate format
		if len(privateKey) != 64 {
			t.Errorf("Invalid private key length for path %s: expected 64 hex chars, got %d", path, len(privateKey))
		}
		
		if !strings.HasPrefix(address, "ARDOR-") {
			t.Errorf("Invalid address format for path %s: should start with ARDOR-", path)
		}
		
		// Check that addresses are unique
		for _, otherPath := range testPaths {
			if otherPath != path {
				otherPrivateKey, otherAddress, err := GetPrivateKeyAndAddress(mnemonic, otherPath)
				if err == nil {
					if privateKey == otherPrivateKey {
						t.Errorf("Private keys should be unique: paths %s and %s generated same key", path, otherPath)
					}
					if address == otherAddress {
						t.Errorf("Addresses should be unique: paths %s and %s generated same address", path, otherPath)
					}
				}
			}
		}
		
		t.Logf("Path %s -> Address: %s", path, address)
	}
}

func TestReedSolomonEncoding(t *testing.T) {
	// Test Reed-Solomon encoding with known account ID/address pairs
	testCases := []struct {
		accountID string
		expected  string
	}{
		{
			accountID: "8745559401709057104",
			expected:  "ARDOR-6F4J-Y4GH-SVZK-9RMRL",
		},
	}
	
	for _, tc := range testCases {
		result, err := EncodeReedSolomon(tc.accountID)
		if err != nil {
			t.Errorf("Failed to encode account ID %s: %v", tc.accountID, err)
			continue
		}
		
		if result != tc.expected {
			t.Errorf("Reed-Solomon encoding mismatch for %s. Expected: %s, Got: %s", 
				tc.accountID, tc.expected, result)
		}
	}
}