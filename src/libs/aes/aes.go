package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

type Aes struct {
	block cipher.Block
}

func NewAesCipher(key string) (*Aes, error) {
	block, err := aes.NewCipher([]byte(key))

	//TODO: AES-256는 key가 32 Bytes 이어야 함
	if len(key) != 32 {
		return nil, errors.New("AES-256 needs a key of 32 bytes")
	}

	if err != nil {
		return nil, err
	}

	return &Aes{
		block: block,
	}, nil
}

func (a *Aes) Encrypt(plaintext []byte) []byte {
	if mod := len(plaintext) % aes.BlockSize; mod != 0 { // 블록 크기의 배수가 되어야함
		padding := make([]byte, aes.BlockSize-mod) // 블록 크기에서 모자라는 부분을
		plaintext = append(plaintext, padding...)  // 채워줌
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext)) // 초기화 벡터 공간(aes.BlockSize)만큼 더 생성
	iv := ciphertext[:aes.BlockSize]                         // 부분 슬라이스로 초기화 벡터 공간을 가져옴
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {  // 랜덤 값을 초기화 벡터에 넣어줌
		fmt.Println(err)
		return nil
	}

	mode := cipher.NewCBCEncrypter(a.block, iv)             // 암호화 블록과 초기화 벡터를 넣어서 암호화 블록 모드 인스턴스 생성
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext) // 암호화 블록 모드 인스턴스로
	// 암호화

	return ciphertext
}

func (a *Aes) Decrypt(ciphertext []byte) []byte {
	if len(ciphertext)%aes.BlockSize != 0 { // 블록 크기의 배수가 아니면 리턴
		fmt.Println("암호화된 데이터의 길이는 블록 크기의 배수가 되어야합니다.")
		return nil
	}

	iv := ciphertext[:aes.BlockSize]        // 부분 슬라이스로 초기화 벡터 공간을 가져옴
	ciphertext = ciphertext[aes.BlockSize:] // 부분 슬라이스로 암호화된 데이터를 가져옴

	plaintext := make([]byte, len(ciphertext))  // 평문 데이터를 저장할 공간 생성
	mode := cipher.NewCBCDecrypter(a.block, iv) // 암호화 블록과 초기화 벡터를 넣어서
	// 복호화 블록 모드 인스턴스 생성
	mode.CryptBlocks(plaintext, ciphertext) // 복호화 블록 모드 인스턴스로 복호화

	return plaintext
}
