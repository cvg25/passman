// Servidor
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

// ServerPassword clave de 32 bytes para AES
const ServerPasword string = "e661e42b6cd1a627512d70462074fa22"

type user struct {
	Username [16]byte
	Password [256]byte
}

//Encriptar usando AES
func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

//Desencriptar usando AES
func decrypt(data []byte, passphrase string) []byte {
	key := []byte(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encryptFile(filename string, data []byte, passphrase string) {
	var fout *os.File // fichero de salida
	var err error     // receptor de error

	// abrimos el fichero de salida
	fout, err = os.Open(filename)
	// Si no existe el fichero, lo creamos.
	if os.IsNotExist(err) {
		fout, err = os.Create(filename)
	}
	// Si se produce algun error abortamos.
	if err != nil {
		panic(err)
	}
	defer fout.Close()

	fout.Write(encrypt(data, passphrase))
}

func decryptFile(filename string, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)
	return decrypt(data, passphrase)
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there!")
}

func main() {
	buf := &bytes.Buffer{}
	persona := user{}
	copy(persona.Username[:], "carlosV")
	copy(persona.Password[:], "clavesecreta")
	jsonPersona, err := json.Marshal(persona)
	err = binary.Write(buf, binary.LittleEndian, jsonPersona)
	if err != nil {
		panic(err)
	}
	encryptFile("usuarios", buf.Bytes(), ServerPasword)
	byt := decryptFile("usuarios", ServerPasword)

	fmt.Printf("Desenc: %s\n", byt)

	personaDecrypt := user{}
	json.Unmarshal(byt, &personaDecrypt)

	fmt.Println("Username: ", personaDecrypt.Username)
	fmt.Println("clavesecreta: ", personaDecrypt.Password)
	//http.HandleFunc("/", handler)
	//http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", nil)
}
