// Servidor
package main

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there!")
}

//Escribe datos en fichero usuarios
func escribeFichero(nombreFichero string, datos []byte) {
	var fout *os.File // fichero de salida
	var err error     // receptor de error

	// abrimos el fichero de salida
	fout, err = os.Open(nombreFichero)
	// Si no existe el fichero, lo creamos.
	if os.IsNotExist(err) {
		fout, err = os.Create(nombreFichero)
	}
	// Si se produce algun error abortamos.
	if err != nil {
		panic(err)
	}
	defer fout.Close()

	fout.Write(datos)
}

func main() {
	escribeFichero("usuarios", []byte{115, 111, 109, 101, 10})
	http.HandleFunc("/", handler)
	http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", nil)
}
