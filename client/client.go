// Client

package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

var client *http.Client

func chk(err error) {
	if err != nil {
		panic(err)
	}
}

// función para cifrar con AES
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// Funcion para leer el usuario y la contraseña
func readUserData() (user string, password string) {
	reader := bufio.NewReader(os.Stdin) // reader para la entrada estándar (teclado)

	fmt.Print("Usuario: ")
	user, err := reader.ReadString('\n')
	// Eliminamos el salto de linea
	user = strings.TrimRight(user, "\r\n")
	chk(err)

	fmt.Print("Contraseña: ")
	// Ocultamos la contraseña mientras se escribe
	passwordBytes, err := terminal.ReadPassword(0)
	password = string(passwordBytes)
	fmt.Println()
	chk(err)

	return
}

func register() {
	user, password := readUserData()

	// hash con SHA512 de la contraseña
	key := sha512.Sum512([]byte(password))
	keyLogin := key[:32]  // una mitad para el login (256 bits)
	keyData := key[32:64] // la otra para los datos (256 bits)

	// generamos un par de claves (privada, pública) para el servidor
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	privateKey.Precompute() // aceleramos su uso con un precálculo

	privkJSON, err := json.Marshal(&privateKey) // codificamos con JSON
	chk(err)

	publicKey := privateKey.Public()          // extraemos la clave pública por separado
	pubkJSON, err := json.Marshal(&publicKey) // y codificamos con JSON
	chk(err)

	data := url.Values{}                     // estructura para contener los valores
	data.Set("cmd", "register")              // comando (string)
	data.Set("user", user)                   // usuario (string)
	data.Set("password", encode64(keyLogin)) // "contraseña" a base64

	// comprimimos y codificamos la clave pública
	data.Set("pubkey", encode64(compress(pubkJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("privkey", encode64(encrypt(compress(privkJSON), keyData)))

	r, err := client.PostForm("https://localhost:8080", data) // enviamos por POST
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	fmt.Println()

}

func login() {
	fmt.Println("Login")
}

func addPassword() {
	fmt.Println("Añadir contraseña")
}

func listPasswords() {
	fmt.Println("Listar contraseñas")
}

func main() {

	// Definicion de los flags
	fRegister := flag.Bool("R", false, "Registro")
	fLogin := flag.Bool("L", false, "Login")
	fAddPasswd := flag.Bool("a", false, "Añadir una contraseña")
	fListPasswds := flag.Bool("ls", false, "Recuperar la lista de contraseñas")

	flag.Parse()

	// Comprobamos si no se ha introducido ninguno
	if !*fRegister && !*fLogin && !*fAddPasswd && !*fListPasswds {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Creamos el cliente
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client = &http.Client{Transport: httpTransport}

	// Operaciones disponibles
	switch {
	case *fRegister:
		register()
	case *fLogin:
		login()
	case *fAddPasswd:
		addPassword()
	case *fListPasswds:
		listPasswords()
	}
}
