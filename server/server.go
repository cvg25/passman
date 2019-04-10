// Servidor
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"

	"golang.org/x/crypto/scrypt"
)

//ListaUsuariosFilename indica el nombre del archivo encriptado que contiene la lista de usuarios de la app
const ficheroUsuarios = "usuarios"

func chk(err error) {
	if err != nil {
		fmt.Println("" + err.Error())
		os.Exit(1)
	}
}

type serverKeysStruct struct {
	Key []byte
	IV  []byte
}

var serverKeys serverKeysStruct

// User estrucutra para los usuarios
type userStruct struct {
	UUID []byte            // identificador de usuario, nombre de fichero personal
	Name string            // nombre de usuario
	Hash []byte            // hash de la contraseña
	Salt []byte            // sal para la contraseña
	Data map[string]string // datos adicionales del usuario
}

//Mapa con todos los usuarios
type usersMap map[string]userStruct

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

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// Registro
func register(w http.ResponseWriter, req *http.Request) {
	uuid, err := exec.Command("uuidgen").Output()
	if err != nil {
		response(w, false, err.Error())
		return
	}
	user := userStruct{}
	user.UUID = uuid
	user.Name = req.Form.Get("user")               // nombre
	user.Salt = make([]byte, 16)                   // sal (16 bytes == 128 bits)
	rand.Read(user.Salt)                           // la sal es aleatoria
	user.Data = make(map[string]string)            // reservamos mapa de datos de usuario
	password := decode64(req.Form.Get("password")) // contraseña (keyLogin)

	// "hasheamos" la contraseña con scrypt
	user.Hash, _ = scrypt.Key(password, user.Salt, 16384, 8, 1, 32)

	resultado, err := registrarUsuario(user)
	if err != nil {
		response(w, resultado, err.Error())
		return
	}
	response(w, resultado, "Usuario registrado con exito.")
}

func obtenerNombreFicheroUsuario(name string) (string, error) {

	listaUsuarios, err := obtenerListaUsuarios()
	if err != nil {
		return "", err
	}

	if usuario, existe := listaUsuarios[name]; existe {

		return "user_" + string(usuario.UUID), nil
	}

	return "", errors.New("No existe el nombre del fichero")

}

// Manejador para subir archivo de contraseñas
func uploadPasswords(w http.ResponseWriter, req *http.Request) {
	user := req.Form.Get("user")
	password := decode64(req.Form.Get("password"))
	data := decode64(req.Form.Get("data"))

	logeado, err := login(user, password)
	if err != nil {
		response(w, logeado, "Error en el servidor")
		return
	} else {
		//obtenemos el nombre del fichero del usuario
		nombreFichero, err := obtenerNombreFicheroUsuario(user)
		if err != nil {
			response(w, false, "Error en el servidor")
			return
		}
		//Creamos el fichero
		var fout *os.File
		fout, err = os.Create(nombreFichero)
		if err != nil {
			response(w, false, err.Error())
			return
		}
		defer fout.Close()
		//Escribimos los datos
		fout.Write(data)

		response(w, true, "Se ha añadido correctamente")
	}
}

// Manejador para recuperar archivo de contraseñas
func downloadPasswords(w http.ResponseWriter, req *http.Request) {
	user := req.Form.Get("user")
	password := decode64(req.Form.Get("password"))

	logeado, err := login(user, password)
	if err != nil {
		response(w, logeado, err.Error())
	} else {
		nombreFichero, err := obtenerNombreFicheroUsuario(user)
		if err != nil {
			response(w, false, "Error en el servidor")
			return
		}
		//Comprobamos si existe el fichero de usuarios
		_, err = os.Stat(nombreFichero)
		if !os.IsNotExist(err) {
			//Si que existe, lo abrimos y leemos todo.
			data, err := ioutil.ReadFile(nombreFichero)
			if err != nil {
				response(w, false, "Error en el servidor")
				return
			}

			response(w, true, encode64(data))
		} else {
			response(w, true, encode64([]byte{}))
		}
	}
}

// Manejador de las peticiones
func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		register(w, req)
	case "uploadPasswords": // ** Subir archivo de contraseñas
		uploadPasswords(w, req)
	case "downloadPasswords": // ** Recuperar archivo de contraseñas
		downloadPasswords(w, req)
	default:
		response(w, false, "Comando inválido")
	}
}

// Login
func login(name string, password []byte) (bool, error) {
	// Obtenemos la lista de usuarios
	listaUsuarios, err := obtenerListaUsuarios()
	if err != nil {
		return false, err
	}

	// Comprobamos si existe
	if _, existe := listaUsuarios[name]; existe {
		salt := listaUsuarios[name].Salt
		hash, _ := scrypt.Key(password, salt, 16384, 8, 1, 32)

		// Comparamos el hash del password con el salt
		if bytes.Compare(hash, listaUsuarios[name].Hash) == 0 {
			return true, nil
		} else {
			return false, errors.New("Credenciales inválidas")
		}
	} else {
		return false, errors.New("Credenciales inválidas")
	}
}

// Guarda un usuario en un fichero encriptado con nombre "usuarios"
func registrarUsuario(usuario userStruct) (bool, error) {

	//Cargamos la lista de usuarios descifrada
	listaUsuarios, err := obtenerListaUsuarios()
	if err != nil {
		return false, err
	}

	if _, existe := listaUsuarios[usuario.Name]; existe {
		return false, errors.New("El nombre de usuario ya existe")
	}
	//Metemos el nuevo usuario en la lista de usuarios
	listaUsuarios[usuario.Name] = usuario

	//Convertimos a JSON la lista
	listaUsuariosJSON, err := json.Marshal(listaUsuarios)

	//Creamos el fichero
	var fout *os.File
	fout, err = os.Create(ficheroUsuarios)
	if err != nil {
		return false, err
	}
	defer fout.Close()

	//Cifrar AES256 y escribir
	var S cipher.Stream
	block, err := aes.NewCipher(serverKeys.Key)
	if err != nil {
		return false, err
	}
	S = cipher.NewCTR(block, serverKeys.IV[:16])
	var rd io.Reader
	var wr io.WriteCloser
	var enc cipher.StreamWriter
	enc.S = S
	enc.W = fout

	rd = bytes.NewReader(listaUsuariosJSON)

	wr = zlib.NewWriter(enc)
	_, err = io.Copy(wr, rd)
	if err != nil {
		return false, err
	}
	wr.Close()

	return true, nil

}

// obtenerListaUsuarios obtiene la lista de usuarios que ya existen o devuelve una lista vacia, si no existe ninguno.
func obtenerListaUsuarios() (usersMap, error) {

	listaUsuarios := make(map[string]userStruct)

	//Comprobamos si existe el fichero de usuarios
	_, err := os.Stat(ficheroUsuarios)
	if !os.IsNotExist(err) {
		//Si que existe, abrimos el fichero para descifrarlo y devolver la lista de usuarios.
		var fin *os.File
		fin, err = os.Open(ficheroUsuarios)
		if err != nil {
			return nil, err
		}
		defer fin.Close()
		//Desciframos
		var S cipher.Stream
		block, err := aes.NewCipher(serverKeys.Key)
		if err != nil {
			return nil, err
		}
		S = cipher.NewCTR(block, serverKeys.IV[:16])

		var rd io.Reader
		var dec cipher.StreamReader
		dec.S = S
		dec.R = fin

		var dst bytes.Buffer

		rd, err = zlib.NewReader(dec)
		if err != nil {
			return nil, err
		}

		_, err = io.Copy(&dst, rd)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(dst.Bytes(), &listaUsuarios)
		if err != nil {
			return nil, err
		}
	}

	return listaUsuarios, nil
}

func main() {
	//flags
	pK := flag.String("k", "", "clave del servidor para cifrar y descifrar")

	flag.Parse()

	if *pK == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// hash de clave e IV (vector de inicialización)
	h := sha256.New()
	h.Reset()
	_, err := h.Write([]byte(*pK))
	chk(err)
	key := h.Sum(nil)

	h.Reset()
	_, err = h.Write([]byte("<inicializar>"))
	chk(err)
	iv := h.Sum(nil)

	//Guardamos las claves generadas en una variable global
	serverKeys = serverKeysStruct{Key: key, IV: iv}

	/* Obtenemos la lista de usuarios, de esta forma, conseguimos que
	 * si la contraseña utilizada para iniciar el servidor es errónea,
	 * de un error porque no puede descifrar la lista.
	 */
	_, err = obtenerListaUsuarios()
	if err != nil {
		fmt.Println("Contraseña inválida")
		os.Exit(1)
	}

	http.HandleFunc("/", handler)
	chk(http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", nil))
}
