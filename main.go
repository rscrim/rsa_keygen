/* DESCRIPTION:
This program generates RSA key pairs with user-selected key lengths.
The user can select a key length from a pre-defined list of allowed lengths.
The program outputs the private and public keys in PEM format.

Author: rscrim@
Date: December 7, 2020
Version: 2.0 */

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

var (
	keyLengths = []int{2048, 3072, 4096} // Allowed key lengths in bits.
)

// encodePrivateKey encodes an RSA private key to PEM format.
// The resulting PEM block has a "RSA PRIVATE KEY" header.
func encodePrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	return pem.EncodeToMemory(block), nil
}

// encodePublicKey encodes an RSA public key to PEM format.
// The resulting PEM block has a "PUBLIC KEY" header.
func encodePublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %s", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}
	return pem.EncodeToMemory(block), nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Welcome to the custom RSA key generator!")
	fmt.Println("-----------------------------------------")

	for {
		// Print main menu.
		fmt.Println("RSA Key Generator")
		fmt.Println("-----------------")
		fmt.Println("1. Generate new key pair")
		fmt.Println("2. Exit")

		// Read user input.
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
		input = input[:len(input)-1] // Remove newline character.

		// Get the bit length for the key
		bitLength := readIntInput(reader, "Enter the bit length for the key (e.g., 2048): ", 512, 4096)

		// Generate the RSA key pair
		publicKey, privateKey := generateKeyPair(bitLength)

		// Ask for a password to protect the private key
		fmt.Print("Enter a password to protect your private key (leave empty for no password): ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		// Convert and optionally encrypt the private key
		var privateKeyPEM []byte
		if password != "" {
			privateKeyPEM = encryptPrivateKey(privateKey, password)
		} else {
			privateKeyPEM = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			})
		}

		// Convert the public key to PEM format
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(publicKey),
		})

		// Export the keys to files
		exportKeyToFile(publicKeyPEM, "public.pem")
		exportKeyToFile(privateKeyPEM, "private.pem")

		fmt.Println("Your keys have been generated and saved to public.pem and private.pem.")
	}
}

func readIntInput(reader *bufio.Reader, prompt string, min int, max int) int {
	for {
		fmt.Print(prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			continue
		}
		input = strings.TrimSpace(input)
		value, err := strconv.Atoi(input)
		if err != nil || value < min || value > max {
			fmt.Printf("Please enter a valid integer between %d and %d.\n", min, max)
			continue
		}
		return value
	}
}

// PublicKey and PrivateKey structures
type PublicKey struct {
	E int64
	N int64
}

type PrivateKey struct {
	D int64
	N int64
}

// Generate an RSA key pair of the given bit length
func generateKeyPair(bits int) (*rsa.PublicKey, *rsa.PrivateKey) {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Println("Error generating RSA keys:", err)
		os.Exit(1)
	}

	// Extract the public key from the private key
	publicKey := &privateKey.PublicKey

	return publicKey, privateKey
}

func encryptPrivateKey(privateKey *rsa.PrivateKey, password string) []byte {
	// Convert the private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	// Encrypt the PEM block with a password
	encryptedPEM, err := x509.EncryptPEMBlock(
		rand.Reader,
		"RSA PRIVATE KEY",
		privateKeyPEM,
		[]byte(password),
		x509.PEMCipherAES256,
	)
	if err != nil {
		fmt.Println("Error encrypting private key:", err)
		os.Exit(1)
	}

	return pem.EncodeToMemory(encryptedPEM)
}

func exportKeyToFile(key []byte, filename string) {
	err := ioutil.WriteFile(filename, key, 0600)
	if err != nil {
		fmt.Println("Error exporting key:", err)
		os.Exit(1)
	}
}

func importKeyFromFile(filename string) []byte {
	key, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error importing key:", err)
		os.Exit(1)
	}
	return key
}
