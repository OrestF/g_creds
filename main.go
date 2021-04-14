package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
)
func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

func writeToFile(filename string, text string) {
	f, err := os.Create(filename)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	_, err2 := f.WriteString(text)

	if err2 != nil {
		log.Fatal(err2)
	}

	fmt.Println("File written")
}

func genSecret() []byte {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		// handle error here
	}

	//fmt.Printf("%x", key)
	sec, err := generateRandomString(32)

	return []byte(sec)
}

func encryptCredentials() {
	infile, err := os.Open(".env")
	if err != nil {
		log.Fatal(err)
	}
	defer infile.Close()

	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	var key []byte
	key, err = ioutil.ReadFile("secret.key")
	if err != nil {
		//log.Fatal(err)
		key = genSecret()
		writeToFile("secret.key", string(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
	}

	outfile, err := os.OpenFile("ciphertext.enc", os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()

	// The buffer size must be multiple of 16 bytes
	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			// Write into file
			outfile.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			break
		}
	}
	// Append the IV
	outfile.Write(iv)
}

func encryptSmall() {
	log.Print("File encryption example")

	plaintext, err := ioutil.ReadFile(".env")
	if err != nil {
		log.Fatal(err)
	}

	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	var key []byte
	key, err = ioutil.ReadFile("secret.key")
	if err != nil {
		//log.Fatal(err)
		key = genSecret()
		writeToFile("secret.key", string(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic(err)
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	// Save back to file
	err = ioutil.WriteFile(".env.encrypted", ciphertext, 0777)
	//writeToFile(".env.enc", string(ciphertext))
	if err != nil {
		log.Panic(err)
	}
}

func decryptCredentials() {
	ciphertext, err := ioutil.ReadFile(".env.encrypted")
	if err != nil {
		log.Fatal(err)
	}

	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	key, err := ioutil.ReadFile("secret.key")
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic(err)
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Panic(err)
	}

	err = ioutil.WriteFile(".env.decrypted", plaintext, 0777)
	if err != nil {
		log.Panic(err)
	}
}

func loadToEnv() {
	err := godotenv.Load(".env.decrypted")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {
	encryptSmall()
	decryptCredentials()
	loadToEnv()
	//encryptCredentials()
}
