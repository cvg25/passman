// Client

package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

var client *http.Client

// Resp estructura para la respuesta del servidor
type Resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

// PasswordData datos que contienen la informacion de una password
type PasswordData struct {
	User     string
	Password string
	Web      string
	Notes    string
}

// PasswordsList contiene una lista de passwords
type PasswordsList []PasswordData

func chk(err error) {
	if err != nil {
		fmt.Println("ERROR: " + err.Error())
		os.Exit(1)
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

// función para descifrar (con AES en este caso)
func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// función para descomprimir
func decompress(data []byte) []byte {
	var b bytes.Buffer // b contendrá los datos descomprimidos

	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer

	chk(err)         // comprobamos el error
	io.Copy(&b, r)   // copiamos del descompresor (r) al buffer (b)
	r.Close()        // cerramos el lector (buffering)
	return b.Bytes() // devolvemos los datos descomprimidos
}

// Funcion para leer el usuario y la contraseña
func readUserCredentials() (user string, password string) {
	reader := bufio.NewReader(os.Stdin) // reader para la entrada estándar (teclado)

	fmt.Print("Usuario de Passman: ")
	user, err := reader.ReadString('\n')
	// Eliminamos el salto de linea
	user = strings.TrimRight(user, "\r\n")
	chk(err)

	fmt.Print("Contraseña de Passman: ")
	// Ocultamos la contraseña mientras se escribe
	passwordBytes, err := terminal.ReadPassword(0)
	password = string(passwordBytes)
	fmt.Println()
	chk(err)

	return
}

// Funcion para leer los datos de la nueva contraseña que quiere añadir el usuario
func readUserData() PasswordData {
	reader := bufio.NewReader(os.Stdin) // reader para la entrada estándar (teclado)
	passwordData := PasswordData{}

	fmt.Println()
	fmt.Println("Introduce los datos de la contraseña:")

	fmt.Print("Usuario: ")
	user, err := reader.ReadString('\n')
	// Eliminamos el salto de linea
	passwordData.User = strings.TrimRight(user, "\r\n")
	chk(err)

	fmt.Print("Contraseña: ")
	// Ocultamos la contraseña mientras se escribe
	passwordBytes, err := terminal.ReadPassword(0)
	passwordData.Password = string(passwordBytes)
	fmt.Println()
	chk(err)

	fmt.Print("Web: ")
	web, err := reader.ReadString('\n')
	// Eliminamos el salto de linea
	passwordData.Web = strings.TrimRight(web, "\r\n")
	chk(err)

	fmt.Print("Notas (opcional): ")
	notas, err := reader.ReadString('\n')
	// Eliminamos el salto de linea
	passwordData.Notes = strings.TrimRight(notas, "\r\n")
	chk(err)

	return passwordData
}

func register() {
	user, password := readUserCredentials()
	// hash con SHA512 de la contraseña
	key := sha512.Sum512([]byte(password))
	keyLogin := key[:32] // una mitad para el login (256 bits)

	data := url.Values{}                     // estructura para contener los valores
	data.Set("cmd", "register")              // comando (string)
	data.Set("user", user)                   // usuario (string)
	data.Set("password", encode64(keyLogin)) // "contraseña" a base64

	resp, err := client.PostForm("https://localhost:8080", data) // enviamos por POST
	chk(err)

	// Leemos el cuerpo y mostramos el mensaje
	body, _ := ioutil.ReadAll(resp.Body)
	r := Resp{}
	json.Unmarshal(body, &r)
	fmt.Println(r.Msg)
}

func addPassword() {
	user, password := readUserCredentials()

	passwordsList, err := downloadPasswords(user, password)
	if err != nil {
		chk(err)
	}
	passwordData := readUserData()
	passwordsList = append(passwordsList, passwordData)
	passwordListJSON, err := json.Marshal(&passwordsList)
	chk(err)

	// hash con SHA512 de la contraseña
	key := sha512.Sum512([]byte(password))
	keyLogin := key[:32]  // una mitad para el login (256 bits)
	keyData := key[32:64] // la otra mitad para el cifrado de datos

	data := url.Values{}                                                     // estructura para contener los valores
	data.Set("cmd", "uploadPasswords")                                       // comando (string)
	data.Set("user", user)                                                   // usuario (string)
	data.Set("password", encode64(keyLogin))                                 // "contraseña" a base64
	data.Set("data", encode64(encrypt(compress(passwordListJSON), keyData))) // Contiene todos los datos

	resp, err := client.PostForm("https://localhost:8080", data) // enviamos por POST
	chk(err)

	// Leemos el cuerpo y mostramos el mensaje
	body, _ := ioutil.ReadAll(resp.Body)
	r := Resp{}
	json.Unmarshal(body, &r)
	fmt.Println(r.Msg)
}

func downloadPasswords(user string, password string) (PasswordsList, error) {
	// hash con SHA512 de la contraseña
	key := sha512.Sum512([]byte(password))
	keyLogin := key[:32]  // una mitad para el login (256 bits)
	keyData := key[32:64] // la otra mitad para el cifrado de datos

	data := url.Values{}                     // estructura para contener los valores
	data.Set("cmd", "downloadPasswords")     // comando (string)
	data.Set("user", user)                   // usuario (string)
	data.Set("password", encode64(keyLogin)) // "contraseña" a base64

	resp, err := client.PostForm("https://localhost:8080", data) // enviamos por POST
	if err != nil {
		return PasswordsList{}, err
	}
	// Leemos el cuerpo y mostramos el mensaje
	body, _ := ioutil.ReadAll(resp.Body)
	r := Resp{}
	json.Unmarshal(body, &r)
	if !r.Ok {
		return PasswordsList{}, errors.New(r.Msg)
	}

	passwordsList := PasswordsList{}
	passwordsDecoded := decode64(r.Msg)
	if len(passwordsDecoded) != 0 {
		passwordsListJSON := decompress(decrypt(passwordsDecoded, keyData))
		json.Unmarshal(passwordsListJSON, &passwordsList)
	}

	return passwordsList, nil
}

func listPasswords() {
	user, password := readUserCredentials()

	passwordsList, err := downloadPasswords(user, password)
	if err != nil {
		chk(err)
	}

	passwordsListJSON, err := json.MarshalIndent(passwordsList, "", "  ")
	if err != nil {
		chk(err)
	}

	if len(passwordsList) == 0 {
		fmt.Println()
		fmt.Println("Todavía no tienes contraseñas guardadas. Prueba a utilizar la opción -a")
	} else {
		fmt.Println()
		fmt.Println("Estas son tus contraseñas:")
		fmt.Println(string(passwordsListJSON))
	}
}

func main() {

	// Definicion de los flags
	fRegister := flag.Bool("R", false, "Registro")
	fAddPasswd := flag.Bool("a", false, "Añadir una contraseña")
	fListPasswds := flag.Bool("ls", false, "Recuperar la lista de contraseñas")

	flag.Parse()

	// Comprobamos si no se ha introducido ninguno
	if !*fRegister && !*fAddPasswd && !*fListPasswds {
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
	case *fAddPasswd:
		addPassword()
	case *fListPasswds:
		listPasswords()
	}
}
