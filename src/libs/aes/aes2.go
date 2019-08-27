package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AESCipher struct {
	block cipher.Block
}

func NewAesCipher(key []byte) (*AESCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &AESCipher{block}, nil
}

func (a *AESCipher) EncryptString(byteString []byte) []byte {
	encryptByteArray := make([]byte, aes.BlockSize+len(byteString))

	iv := encryptByteArray[:aes.BlockSize]

	io.ReadFull(rand.Reader, iv)

	stream := cipher.NewCFBEncrypter(a.block, iv)
	stream.XORKeyStream(encryptByteArray[aes.BlockSize:], byteString)

	return encryptByteArray
}

func (a *AESCipher) DecryptString(byteString []byte) []byte {

	decryptByteArray := make([]byte, len(byteString))
	iv := byteString[:aes.BlockSize]

	stream := cipher.NewCFBDecrypter(a.block, iv)
	stream.XORKeyStream(decryptByteArray, byteString[aes.BlockSize:])

	return decryptByteArray
}
