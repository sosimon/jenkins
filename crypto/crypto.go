/*
Package crypto is used for decrypting and encrypting Jenkins credentials
Requires two keys to function:
  secretKey location: $JENKINS_HOME/secrets/hudson.util.Secret
  masterKey location: $JENKINS_HOME/secrets/master.key
The decryption algorithm was made possible by http://xn--thibaud-dya.fr/jenkins_credentials.html and encryption is simply reversing the decryption steps
*/
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	magic   = "::::MAGIC::::"
	padding = "\n"
)

var ErrUnintializedKeys = errors.New("Either the secret or master key has not been set. Use SetSecretKey() and/or SetMasterKey() to initiatize them before encrypting or decrypting.")

//Crypto struct holds the secret and master key, and the decrypted secret key
//used to encrypt and decrypt Jenkins credentials
type Crypto struct {
	secretKey          string
	masterKey          string
	decryptedSecretKey []byte
}

func (c *Crypto) decryptSecretKey() {
	//hash masterKey
	masterKeyBS := []byte(c.masterKey)
	hash := sha256.New()
	hash.Write(masterKeyBS)
	//take only the first 16 bytes (128-bits), discard everything else
	hashedMasterKey := hash.Sum(nil)[:16]
	//base64 decode secretKey
	secretKeyDecoded, _ := base64.StdEncoding.DecodeString(c.secretKey)
	//decrypt secretKey using the hashed masterKey
	decryptedSecretKey := c.ECBDecrypt(hashedMasterKey, secretKeyDecoded)
	//truncate everything except the first 16 bytes (128-bits)
	c.decryptedSecretKey = decryptedSecretKey[:16]
}

//ECBDecrypt decrypts an encrypted byte slice using the key, and returns the decrypted result
func (c *Crypto) ECBDecrypt(key []byte, encrypted []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	bs := block.BlockSize()
	plainText := make([]byte, len(encrypted))
	head := plainText
	for len(encrypted) > 0 {
		block.Decrypt(plainText, encrypted)
		plainText = plainText[bs:]
		encrypted = encrypted[bs:]
	}
	return head
}

//ECBEncrypt encrypts a plain text byte slice using the key, and returns the encrypted result
func (c *Crypto) ECBEncrypt(key []byte, plainText []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	bs := block.BlockSize()
	plainTextPadded := c.Pad(plainText, bs)
	encrypted := make([]byte, len(plainTextPadded))
	head := encrypted
	for len(plainTextPadded) > 0 {
		block.Encrypt(encrypted, plainTextPadded)
		encrypted = encrypted[bs:]
		plainTextPadded = plainTextPadded[bs:]
	}
	return head
}

//Pad text to blocksize bs
func (c *Crypto) Pad(text []byte, bs int) []byte {
	padded := text
	if len(text)%bs != 0 {
		paddingLen := bs - (len(text) % bs)
		for i := 0; i < paddingLen; i++ {
			padded = append(padded, []byte(padding)...)
		}
	}
	return padded
}

//Decrypt a Jenkins credential - accepts an encrypted string and returns the decrypted string
func (c *Crypto) Decrypt(cipherText string) (string, error) {
	if (c.secretKey == "") || (c.masterKey == "") {
		return "", ErrUnintializedKeys
	}
	if c.decryptedSecretKey == nil {
		c.decryptSecretKey()
	}
	//base64 decode cipherText
	cipherTextDecoded, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		panic(err)
	}
	//decrypt cipherText using decryptedSecretKey
	plainTextBS := c.ECBDecrypt(c.decryptedSecretKey, cipherTextDecoded)
	//throw away all the bytes after magic
	plainTextBS = bytes.Split(plainTextBS, []byte(magic))[0]
	fmt.Printf("Decrypted: %q\n", plainTextBS)
	plainText := string(plainTextBS)
	return plainText, nil
}

//Encrypt a Jenkins credential - accepts a plain text string and returns the encrypted string
func (c *Crypto) Encrypt(plainText string) (string, error) {
	if (c.secretKey == "") || (c.masterKey == "") {
		return "", ErrUnintializedKeys
	}
	if c.decryptedSecretKey == nil {
		c.decryptSecretKey()
	}
	//add magic
	plainText = plainText + magic
	//encrypt plainText using decryptedSecretKey
	encryptedBS := c.ECBEncrypt(c.decryptedSecretKey, []byte(plainText))
	//base64 encode
	encrypted := base64.StdEncoding.EncodeToString(encryptedBS)
	fmt.Printf("Encrypted: %q\n", encrypted)
	return encrypted, nil
}

//SetSecretKey or the contents of $JENKINS_HOME/secrets/hudson.util.Secret
//Expecting the input string to be base64 encoded (hudson.util.Secret is NOT encoded by default)
func (c *Crypto) SetSecretKey(secret string) {
	c.secretKey = secret
}

//SetMasterKey or the contents of $JENKINS_HOME/secrets/master.key
func (c *Crypto) SetMasterKey(master string) {
	c.masterKey = master
}

//SecretKey returns the secretKey, aka $JENKINS_HOME/secrets/hudson.util.Secret
func (c *Crypto) SecretKey() string {
	return c.secretKey
}

//MasterKey returns the masterKey, aka $JENKINS_HOME/secrets/master.key
func (c *Crypto) MasterKey() string {
	return c.masterKey
}
