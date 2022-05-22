package main

import (
	"crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/wealdtech/go-ens/v3"
)

const (
	defaultPort   = "3000"
	nonceAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

//go:embed ui/build
var ui embed.FS

func main() {
	store := newInMemoryStore()

	port := defaultPort
	if customPort := os.Getenv("PORT"); customPort != "" {
		port = customPort
	}

	var ethereumClient *ethclient.Client
	if infuraSecret := os.Getenv("INFURA_SECRET"); infuraSecret != "" {
		var err error
		ethereumClient, err = ethclient.Dial(fmt.Sprintf("https://mainnet.infura.io/v3/%s", infuraSecret))
		if err != nil {
			log.Fatalln("Failed to initialize Ethereum client", err)
		}
	}

	http.Handle("/", indexHandler())
	http.HandleFunc("/api/nonce", nonceHandler(store))
	http.HandleFunc("/api/verify-signature", verifySignatureHandler(store, ethereumClient))

	fmt.Printf("Start listening at http://localhost:%s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalln("Failed to start server", err)
	}
}

func indexHandler() http.Handler {
	contents, _ := fs.Sub(ui, "ui/build")
	return http.FileServer(http.FS(contents))
}

type nonceRequest struct {
	Address string `json:"address"`
}

type nonceResponse struct {
	Nonce string `json:"nonce"`
}

func nonceHandler(store *inMemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := nonceRequest{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			respondWithError(w, http.StatusBadRequest, err)
			return
		}

		nonce, err := generateNonce()
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err)
			return
		}

		store.Set(body.Address, nonce)

		_ = json.NewEncoder(w).Encode(nonceResponse{Nonce: nonce})
	}
}

type verifySignatureRequest struct {
	Address   string `json:"address"`
	Signature string `json:"signature"`
}

type verifySignatureResponse struct {
	ENS string `json:"ens"`
}

func verifySignatureHandler(store *inMemoryStore, ethereumClient *ethclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := verifySignatureRequest{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			respondWithError(w, http.StatusBadRequest, err)
			return
		}

		nonce, err := store.Get(body.Address)
		if err != nil {
			respondWithError(w, http.StatusNotFound, err)
			return
		}

		if err = verifySignature(body.Address, body.Signature, nonce); err != nil {
			respondWithError(w, http.StatusUnauthorized, err)
			return
		}

		store.Remove(body.Address)

		var reverse string
		if ethereumClient != nil {
			// Not an error, if we can't resolve the address to an ENS domain.
			reverse, _ = ens.ReverseResolve(ethereumClient, common.HexToAddress(body.Address))
		}

		_ = json.NewEncoder(w).Encode(verifySignatureResponse{ENS: reverse})
	}
}

func verifySignature(from, sigHex, nonce string) error {
	sig, err := hexutil.Decode(sigHex)
	if err != nil {
		return err
	}

	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1

	pubKey, err := crypto.SigToPub(accounts.TextHash([]byte(nonce)), sig)
	if err != nil {
		return err
	}

	if common.HexToAddress(from) != crypto.PubkeyToAddress(*pubKey) {
		return fmt.Errorf("failed to verify signature")
	}

	return nil
}

func generateNonce() (string, error) {
	nonceBytes := make([]byte, 12)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}

	for idx, b := range nonceBytes {
		nonceBytes[idx] = nonceAlphabet[b%byte(len(nonceAlphabet))]
	}

	return string(nonceBytes), nil
}

func respondWithError(w http.ResponseWriter, statusCode int, err error) {
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(err.Error()))
}
