// Servidor
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

/*

func obtenerListaUsuariosDesencriptada() usersList {

	bytesUsuarios := decryptFile(ListaUsuariosFilename, ServerPasword)
	usuarios := usersList{}
	json.Unmarshal(bytesUsuarios, &usuarios)
	return usuarios
}

func guardarListaUsuariosEncriptada(usuarios usersList) {
	jsonUsuarios, err := json.Marshal(usuarios)

	buf := &bytes.Buffer{}
	err = binary.Write(buf, binary.LittleEndian, jsonUsuarios)
	if err != nil {
		panic(err)
	}
	encryptFile(ListaUsuariosFilename, buf.Bytes(), ServerPasword)
}

func registrarUsuario(username string, password string) {
	//Creamos el nuevo usuario
	usuario := userStruct{}
	copy(usuario.Username[:], username)
	copy(usuario.Password[:], password)
	//Obtenemos la lista de usuarios
	usuarios := obtenerListaUsuariosDesencriptada()
	//Anyadimos el usuario a la lista de usuarios
	usuarios = append(usuarios, usuario)
	//Guardamos la lista de usuarios encriptada
	guardarListaUsuariosEncriptada(usuarios)
}*/

//UsernameMaxSize indica el tamaño máximo de los nombres de usuario
const UsernameMaxSize = 16

//PasswordMaxSize indica el tamaño máximo de las contraseñas
const PasswordMaxSize = 128

//ListaUsuariosFilename indica el nombre del archivo encriptado que contiene la lista de usuarios de la app
const ficheroUsuarios = "usuarios"

type userStruct struct {
	Username [UsernameMaxSize]byte
	Password [PasswordMaxSize]byte
}

type usersList []userStruct

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there!")
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

//Guarda un usuario en un fichero encriptado con nombre "usuarios"
func registrarUsuario(name string, password string, serverKey []byte, iv []byte) {

	//Cargamos la lista de usuarios descifrada
	listaUsuarios := obtenerListaUsuarios(serverKey, iv)

	//Creamos el nuevo usuario
	usuario := userStruct{}
	copy(usuario.Username[:], name)
	copy(usuario.Password[:], password)

	//Metemos el nuevo usuario en la lista de usuarios
	listaUsuarios = append(listaUsuarios, usuario)

	//Convertimos a JSON la lista
	listaUsuariosJSON, err := json.Marshal(listaUsuarios)

	//Creamos el fichero
	var fout *os.File
	fout, err = os.Create(ficheroUsuarios)
	check(err)
	defer fout.Close()

	//Cifrar AES256 y escribir
	var S cipher.Stream
	block, err := aes.NewCipher(serverKey)
	check(err)
	S = cipher.NewCTR(block, iv[:16])
	var rd io.Reader
	var wr io.WriteCloser
	var enc cipher.StreamWriter
	enc.S = S
	enc.W = fout

	rd = bytes.NewReader(listaUsuariosJSON)

	wr = zlib.NewWriter(enc)
	_, err = io.Copy(wr, rd)
	check(err)
	wr.Close()
}

// obtenerListaUsuarios obtiene la lista de usuarios que ya existen o devuelve una lista vacia, si no existe ninguno.
func obtenerListaUsuarios(serverKey []byte, iv []byte) usersList {

	listaUsuarios := usersList{}

	//Comprobamos si existe el fichero de usuarios
	_, err := os.Stat(ficheroUsuarios)
	if !os.IsNotExist(err) {
		//Si que existe, abrimos el fichero para descifrarlo y devolver la lista de usuarios.
		var fin *os.File
		fin, err = os.Open(ficheroUsuarios)
		check(err)
		defer fin.Close()
		//Desciframos
		var S cipher.Stream
		block, err := aes.NewCipher(serverKey)
		check(err)
		S = cipher.NewCTR(block, iv[:16])

		var rd io.Reader
		var dec cipher.StreamReader
		dec.S = S
		dec.R = fin

		var dst bytes.Buffer

		rd, err = zlib.NewReader(dec)
		check(err)

		_, err = io.Copy(&dst, rd)
		check(err)

		err = json.Unmarshal(dst.Bytes(), &listaUsuarios)
	}

	return listaUsuarios
}

func main() {

	//flags
	pK := flag.String("k", "", "clave del servidor para cifrar y descifrar")

	flag.Parse()

	if *pK == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// hash de clave e IV
	h := sha256.New()
	h.Reset()
	_, err := h.Write([]byte(*pK))
	check(err)
	key := h.Sum(nil)

	h.Reset()
	_, err = h.Write([]byte("<inicializar>"))
	check(err)
	iv := h.Sum(nil)

	registrarUsuario("carlos", "root", key, iv)
	listaUsuarios := obtenerListaUsuarios(key, iv)

	fmt.Println(listaUsuarios)
	//http.HandleFunc("/", handler)
	//http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", nil)
}
