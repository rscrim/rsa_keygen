# Custom RSA Key Generator

This program allows you to generate RSA keys interactively.

## How It Works

The program uses the RSA algorithm to generate a pair of keys, a public key for encryption, and a private key for decryption. Here's a step-by-step process:

1. The program first asks you to enter the bit length for the keys. This determines the strength of the keys. A longer key is more secure but slower to use. A common choice for the bit length is 2048 bits.

2. The program generates a pair of RSA keys with the specified bit length.

3. The program asks you to enter a password to protect your private key. This is optional. If you enter a password, the program will use it to encrypt your private key.

4. The program converts the keys to PEM format, which is a widely used format for storing and transmitting cryptographic keys.

5. The program saves the keys to files named "public.pem" and "private.pem". The private key file is encrypted if you have entered a password.

## How to Use

To run the program, use the following command:

```bash
go run rsa.go
```

Follow the prompts to generate your RSA keys.

To import the keys for later use, you can use the `importKeyFromFile` function in the program. For example:

```go
publicKey := importKeyFromFile("public.pem")
privateKey := importKeyFromFile("private.pem")
```

Please note that if your private key is password-protected, you will need to decrypt it using the same password before you can use it.

## Security Considerations

RSA keys are very sensitive information. If someone gets access to your private key, they can read your encrypted messages and impersonate you digitally. Therefore, it's important to keep your private key secure. 

If you choose to protect your private key with a password, make sure to choose a strong password and keep it safe. If you lose the password, you won't be able to use your private key.
