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
	// Configuracion de la conexion
	conf := &tls.Config{
		// InsecureSkipVerify: true,
	}

	// Conexion con el servidor
	conn, err := tls.Dial("tcp", "localhost:1337", conf)
	chk(err)
	defer conn.Close()

	fmt.Println("Conectado a ", conn.RemoteAddr())
}
