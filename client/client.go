// Client

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
)

func chk(err error) {
	if err != nil {
		panic(err)
	}
}

func register() {
	fmt.Println("Registro")
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

	// Cargamos los certificados
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	chk(err)

	// Configuracion de la conexion
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	// Conexion con el servidor
	conn, err := tls.Dial("tcp", "127.0.0.1:8080", conf)
	chk(err)
	defer conn.Close()

	fmt.Println("Conectado a ", conn.RemoteAddr())

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
