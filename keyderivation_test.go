package keyderivation

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestMnemonicDerivation(t *testing.T) {
	// Test mnemonic from JavaScript test suite
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	
	// Test cases from JavaScript test suite
	testCases := []struct {
		path                  string
		expectedPrivateKeyLeft   string
		expectedPrivateKeyRight  string
		expectedChainCode        string
		expectedMasterPublicKey  string
	}{
		{
			path:                  "42'/1/2",
			expectedPrivateKeyLeft:   "b02160bb753c495687eb0b0e0628bf637e85fd3aadac109847afa2ad20e69d41",
			expectedPrivateKeyRight:  "00ea111776aabeb85446b186110f8337a758681c96d5d01d5f42d34baf97087b",
			expectedChainCode:        "c52916b7bb856bd1733390301cdc22fd2b0d5e6fab9908d55fd1bed13bccbb36",
			expectedMasterPublicKey:  "bc738b13faa157ce8f1534ddd9299e458be459f734a5fa17d1f0e73f559a69ee",
		},
		{
			path:                  "42'/3'/5",
			expectedPrivateKeyLeft:   "78164270a17f697b57f172a7ac58cfbb95e007fdcd968c8c6a2468841fe69d41",
			expectedPrivateKeyRight:  "15c846a5d003f7017374d12105c25930a2bf8c386b7be3c470d8226f3cad8b6b",
			expectedChainCode:        "7e64c416800883256828efc63567d8842eda422c413f5ff191512dfce7790984",
			expectedMasterPublicKey:  "286b8d4ef3321e78ecd8e2585e45cb3a8c97d3f11f829860ce461df992a7f51c",
		},
	}
	
	// Test each derivation path from JavaScript test suite
	for _, testCase := range testCases {
		node, err := DeriveMnemonic(testCase.path, mnemonic)
		if err != nil {
			t.Errorf("Failed to derive key for path %s: %v", testCase.path, err)
			continue
		}
		
		actualPrivateKeyLeft := hex.EncodeToString(node.GetPrivateKeyLeft())
		actualPrivateKeyRight := hex.EncodeToString(node.GetPrivateKeyRight())
		actualChainCode := hex.EncodeToString(node.GetChainCode())
		actualMasterPublicKey := hex.EncodeToString(node.GetMasterPublicKey())
		
		fmt.Printf("Path: %s\n", testCase.path)
		fmt.Printf("Private Key Left - Expected: %s, Actual: %s\n", testCase.expectedPrivateKeyLeft, actualPrivateKeyLeft)
		fmt.Printf("Private Key Right - Expected: %s, Actual: %s\n", testCase.expectedPrivateKeyRight, actualPrivateKeyRight)
		fmt.Printf("Chain Code - Expected: %s, Actual: %s\n", testCase.expectedChainCode, actualChainCode)
		fmt.Printf("Master Public Key - Expected: %s, Actual: %s\n", testCase.expectedMasterPublicKey, actualMasterPublicKey)
		fmt.Println()
		
		if actualPrivateKeyLeft != testCase.expectedPrivateKeyLeft {
			t.Errorf("Private key left mismatch for path %s", testCase.path)
		}
		if actualPrivateKeyRight != testCase.expectedPrivateKeyRight {
			t.Errorf("Private key right mismatch for path %s", testCase.path)
		}
		if actualChainCode != testCase.expectedChainCode {
			t.Errorf("Chain code mismatch for path %s", testCase.path)
		}
		if actualMasterPublicKey != testCase.expectedMasterPublicKey {
			t.Errorf("Master public key mismatch for path %s", testCase.path)
		}
	}
}

func TestMnemonicToSeed(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	
	seed := MnemonicToSeed(mnemonic)
	if len(seed) != 64 {
		t.Errorf("Expected seed length 64, got %d", len(seed))
	}
	
	expectedSeed := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	actualSeed := hex.EncodeToString(seed)
	
	if actualSeed != expectedSeed {
		t.Errorf("Seed mismatch")
	}
}

func TestUserProvidedMnemonic(t *testing.T) {
	// Test with the user's original 18-word mnemonic
	mnemonic := "side vast trash guard circle voyage undo behave sustain punch pave club admit fox step letter awake item"
	
	// Expected values from user (these are the correct Curve25519 public keys)
	expectedPublicKeys := map[string]string{
		"m/44'/16754'/0'/0'/0": "1579c39eb74c8d696ad297fc64f382811dd93eb64020eb17ac0531e020812d6a",
		"m/44'/16754'/0'/0'/1": "24d25e6ca1cdb1f38358f2b08a63fd23898853f6a42d853f7786e8d16ba8ef2e",
		"m/44'/16754'/0'/0'/2": "fc817b9d55568f971be3e2b19822d2960e8dd64082d3f73b489deb53f522f447",
		"m/44'/16754'/0'/0'/3": "f674c174b1438eba5d5648199a58e69fffc30c94f451d4d4cb81310fd7bfe010",
		"m/44'/16754'/0'/0'/4": "47a363bab05c710e740d840d69ec132b2891f22c7e63df1c1608bd1f9b17442a",
		"m/44'/16754'/0'/0'/5": "84a93f962411e152860cbeaec47eba1b23e10c2188bdb640efe93c95a9948821",
	}
	
	// Test master key derivation first
	masterNode, err := DeriveMnemonic("m", mnemonic)
	if err != nil {
		t.Fatalf("Failed to derive master node: %v", err)
	}
	
	// Expected master public key (Ed25519 format with X parity bit)
	expectedMasterPubKey := "f057a838365b854c06b06f6d9acace5c4165704c8dfcd876628f891b6dea6f13"
	expectedChainCode := "431c05243c2e7f032f6064aa3ad887e55db3d93739c08360bb8e423c1032c01f"
	
	actualPubKey := hex.EncodeToString(masterNode.GetMasterPublicKey())
	actualChainCode := hex.EncodeToString(masterNode.GetChainCode())
	
	fmt.Printf("Master Public Key - Expected: %s, Actual: %s\n", expectedMasterPubKey, actualPubKey)
	fmt.Printf("Master Chain Code - Expected: %s, Actual: %s\n", expectedChainCode, actualChainCode)
	
	if actualPubKey != expectedMasterPubKey {
		t.Errorf("Master public key mismatch")
	}
	if actualChainCode != expectedChainCode {
		t.Errorf("Master chain code mismatch")
	}
	
	// Test each derivation path
	for path, expectedPubKey := range expectedPublicKeys {
		node, err := DeriveMnemonic(path, mnemonic)
		if err != nil {
			t.Errorf("Failed to derive key for path %s: %v", path, err)
			continue
		}
		
		actualPubKey := hex.EncodeToString(node.GetPublicKey())
		fmt.Printf("Path %s - Expected: %s, Actual: %s\n", path, expectedPubKey, actualPubKey)
		
		if actualPubKey != expectedPubKey {
			t.Errorf("Public key mismatch for path %s", path)
		}
	}
}

func TestPathParsing(t *testing.T) {
	testPaths := []string{
		"m/44'/16754'/0'/0'/0",
		"m/44'/16754'/0'/0'/1",
		"m/0",
		"m/1'",
	}
	
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	
	for _, path := range testPaths {
		_, err := DeriveMnemonic(path, mnemonic)
		if err != nil {
			t.Errorf("Failed to parse path %s: %v", path, err)
		} else {
			fmt.Printf("Successfully parsed path: %s\n", path)
		}
	}
}