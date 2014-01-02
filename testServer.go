package main

import (
	"fmt"
	"goIn"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
}
func badhandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
}
func main() {
	pm := goIn.PasswordMiddleware{}
	http.ListenAndServe(":8000", http.HandlerFunc(pm.Auth(handler, badHandler)))

}
