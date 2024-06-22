package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

const (
	secretKey = "secret-key"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", register)
	mux.HandleFunc("/validate", validate)

	http.ListenAndServe(":9000", mux)
}

func register(w http.ResponseWriter, r *http.Request) {
	id := uuid.NewString()
	exp := time.Now().Add(1 * time.Minute).UnixNano()

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s_%d_%s", id, exp, secretKey)))

	signS := fmt.Sprintf("%x", h.Sum(nil))

	urlValidate := fmt.Sprintf("http://localhost:9000/validate?id=%s&exp=%d&sign=%s", id, exp, signS)

	w.Write([]byte(urlValidate))
}

func validate(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	hashS := r.URL.Query().Get("sign")
	expD := r.URL.Query().Get("exp")

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s_%s_%s", id, expD, secretKey)))

	expIn, _ := strconv.Atoi(expD)
	if int64(expIn) < time.Now().UnixNano() {
		w.WriteHeader(400)
		w.Write([]byte("url expired"))
	}

	signS := fmt.Sprintf("%x", h.Sum(nil))

	if signS != hashS {
		w.WriteHeader(400)
		w.Write([]byte("invalid signature"))
	} else {
		w.WriteHeader(200)
		w.Write([]byte("success registration"))
	}
}
