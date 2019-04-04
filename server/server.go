// Servidor
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"golang.org/x/crypto/scrypt"
)

func chk(err error) {
	if err != nil {
		panic(err)
	}
}

// User estrucutra para los usuarios
type User struct {
	Name string            // nombre de usuario
	Hash []byte            // hash de la contraseña
	Salt []byte            // sal para la contraseña
	Data map[string]string // datos adicionales del usuario
}

// Resp estructura para la respuesta del servidor
type Resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string) {
	r := Resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// Registro
func register(w http.ResponseWriter, req *http.Request) {
	user := User{}
	user.Name = req.Form.Get("user")               // nombre
	user.Salt = make([]byte, 16)                   // sal (16 bytes == 128 bits)
	rand.Read(user.Salt)                           // la sal es aleatoria
	user.Data = make(map[string]string)            // reservamos mapa de datos de usuario
	user.Data["private"] = req.Form.Get("privkey") // clave privada
	user.Data["public"] = req.Form.Get("pubkey")   // clave pública
	password := decode64(req.Form.Get("password")) // contraseña (keyLogin)

	// "hasheamos" la contraseña con scrypt
	user.Hash, _ = scrypt.Key(password, user.Salt, 16384, 8, 1, 32)

	response(w, false, "Aqui se registra el usuario")
}

// Manejador de las peticiones
func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		register(w, req)
	default:
		response(w, false, "Comando inválido")
	}
}

func main() {
	http.HandleFunc("/", handler)
	chk(http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", nil))
}
