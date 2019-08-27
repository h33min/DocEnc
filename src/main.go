package main

import (
	"fmt"

	"libs/aes"

	"io/ioutil"
	"libs/sssa"
	"os"

	log "github.com/sirupsen/logrus"
)

var extensions = []string{".doc", ".doxs", ".html", ".htm", ".odt", ".pdf", ".xls", ".xlsx", ".ods", ".ppt", ".pptx", ".txt", ".jpeg", ".jpg", ".png"}

/* File Extension List */
/*
.DOC and .DOCX.	// 0 1
.HTML and .HTM.	// 2 3
.ODT.			// 4
.PDF.			// 5
.XLS and XLSX.	// 6 7
.ODS.			// 8
.PPT and .PPTX.	// 9 10
.TXT.			// 11
.JPEG and .JPG	// 12 13
.PNG			// 14
*/

var filename = "ppttest"
var extension = extensions[9]

// var extension = ".hwp"
// var extension = ".ppt"
// var extension = ".pptx"
// var extension = ".txt"
// var extension = ".png"
// var extension = ".jpg"
// var extension = ".doc"
// var extension = ".zip"

var path = "/Users/heemin/DocSec/src/" + filename + extension
var encPath = "/Users/heemin/DocSec/src/enc-" + filename + extension
var decPath = "/Users/heemin/DocSec/src/dec-" + filename + extension

func main() {

	//Define a aeskey
	var aeskey = "AES256KEY-MUST32Characters777777" //AES256Key-32Characters1234567890"

	//Encrypt a Document
	encDoc(aeskey)

	//Create SSSKeys
	allkeys := generateSharedKey(3, 5, aeskey)

	//Pick PatialKeys from allKeys
	patialkeyss := allkeys[0:3]

	//Recover a aeskey
	recoveredKey := combineSharedKey(patialkeyss)

	//Decrypta  Documeny
	decDoc(recoveredKey)

}

//Create Secret Shared keys with aeskey
func generateSharedKey(k int, n int, aeskey string) []string {
	keys, _ := sssa.Create(k, n, aeskey)

	for i, key := range keys {
		log.WithFields(log.Fields{
			"idx":        i,
			"shared key": key,
		}).Info("Create Secret shared key with aeskey")
	}
	return keys
}

//Combine Secret Shared keys
func combineSharedKey(sharedKeys []string) string {
	recoveredKey, _ := sssa.Combine(sharedKeys)
	log.WithFields(log.Fields{
		"sharedKeys":   fmt.Sprintf("%+v", sharedKeys),
		"recoveredKey": recoveredKey,
	}).Info("Combine Secret shared key")

	return recoveredKey
}

//Encrypt a Document with AES-256
func encDoc(aeskey string) {
	log.WithFields(log.Fields{
		"aeskey": aeskey,
	}).Info("Encrypt File with AES-256")

	bytes := fileRead(path)

	log.WithFields(log.Fields{
		"byte": len(bytes),
	}).Info("Original File - Bytes")

	//aesObj, _ := aes.NewAesCipher([]byte(aeskey))
	//ciphertext := aesObj.EncryptString(bytes)

	ciphertext, err := aes.Encrypt([]byte(aeskey), bytes) // 평문을 AES 알고리즘으로 암호화
	if err != nil {
		return
	}

	log.WithFields(log.Fields{
		"byte": len(ciphertext),
	}).Info("CipherText File - Bytes")

	fileWrite(encPath, []byte(ciphertext), 0777)

}

//Decrypt a Document with AES-256
func decDoc(aeskey string) {
	log.WithFields(log.Fields{
		"aeskey": aeskey,
	}).Info("Decrypt File with AES-256")

	bytes := fileRead(encPath)

	log.WithFields(log.Fields{
		"byte": len(bytes),
	}).Info("Bytes EncFile")

	//aesObj, _ := aes.NewAesCipher([]byte(aeskey))
	//plaintext := aesObj.DecryptString(bytes)
	plaintext, err := aes.Decrypt([]byte(aeskey), bytes) // AES 알고리즘 암호문을 평문으로 복호화
	if err != nil {
		return
	}
	log.WithFields(log.Fields{
		"byte": len(plaintext),
	}).Info("Recovered Byte")

	fileWrite(decPath, []byte(plaintext), 0777)
}

//Read a file
func fileRead(path string) []byte {
	log.WithFields(log.Fields{
		"Read File": path,
	}).Info("Read File")

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return bytes
}

//Write a file
func fileWrite(path string, text []byte, mod os.FileMode) {
	log.WithFields(log.Fields{
		"Write File":  path,
		"os.Filemode": mod,
	}).Info("Write File")

	err := ioutil.WriteFile(path, text, mod)
	if err != nil {
		panic(err)
	}
}
