// Client

package main

import (
	"crypto/tls"
	"fmt"
)

func chk(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
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
}
