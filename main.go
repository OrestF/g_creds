package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
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

func writeToFile(filename string, text []byte) {
	ioutil.WriteFile(filename, text, 0777)
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


func sourceEnvFileName(environment string) string{
	return ".env." + environment
}

func outputEnvFileName(environment string) string {
	return sourceEnvFileName(environment) + ".enc"
}

func encKeyName(environment string) string {
	return environment + ".key"
}

func encryptCredentials(environment string) []byte {
	//log.Print("File encryption example")

	byteText, err := ioutil.ReadFile(sourceEnvFileName(environment))
	if err != nil {
		log.Fatal(err)
	}

	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	var key []byte
	key, err = ioutil.ReadFile(encKeyName(environment))
	if err != nil {
		//log.Fatal(err)
		key = genSecret()
		writeToFile(encKeyName(environment), key)
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

	ciphertext := gcm.Seal(nonce, nonce, byteText, nil)
	// Save back to file
	//err = ioutil.WriteFile(".env.development.encrypted", ciphertext, 0777)
	//writeToFile(".env.development.enc", string(ciphertext))
	if err != nil {
		log.Panic(err)
	}

	return ciphertext
}

func decryptCredentials(ciphertext []byte, environment string) []byte {
	//ciphertext, err := ioutil.ReadFile(".env.development.encrypted")
	//if err != nil {
	//	log.Fatal(err)
	//}

	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	key, err := ioutil.ReadFile(encKeyName(environment))
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
	decryptedCredentialsText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Panic(err)
	}

	//err = ioutil.WriteFile(".env.development.decrypted", decryptedCredentialsText, 0777)
	//if err != nil {
	//	log.Panic(err)
	//}

	return decryptedCredentialsText
}

func loadToEnv(decryptedCredentials []byte) {
	//err := godotenv.Load(".env.development.decrypted")
	//if err != nil {
	//	log.Fatal("Error loading .env.development file")
	//}
	credentialsMap, _ := godotenv.Unmarshal(string(decryptedCredentials))
	for key, value := range credentialsMap {
		os.Setenv(key, value)
	}
}

func saveEncryptedToFile(ciphertext []byte, environment string) {
	writeToFile(outputEnvFileName(environment), ciphertext)
}

func decryptFromFile(environment string) []byte {
	byteText, err := ioutil.ReadFile(outputEnvFileName(environment))
	if err != nil {
		log.Fatal(err)
	}

	return decryptCredentials(byteText, environment)
}

func encryptScenario(environment string) {
	encryptedCredentials := encryptCredentials(environment)
	saveEncryptedToFile(encryptedCredentials, environment)
	log.Print("Encrypted")
}

func loadScenario(environment string) {
	decryptedCredentials := decryptFromFile(environment)
	loadToEnv(decryptedCredentials)
	log.Print("Loaded")
}

func decryptScenario(environment string) {
	decryptedCredentials := decryptFromFile(environment)
	writeToFile(sourceEnvFileName(environment), decryptedCredentials)
	log.Print("Decrypted")
}

func showScenario(environment string) {
	decryptedCredentials := decryptFromFile(environment)
	credentialsMap, _ := godotenv.Unmarshal(string(decryptedCredentials))
	for key, value := range credentialsMap {
		fmt.Println(key, "=", value)
	}
}

func main() {

	action := flag.String("action", "encrypt", "Encrypt file")
	environment := flag.String("environment", "development", "Environment declaration")

	flag.Parse()
	//fmt.Println(*action)
	//fmt.Println(*environment)
	//fmt.Println(flag.Args())

	switch *action {
	case "encrypt":
		encryptScenario(*environment)
	case "load":
		loadScenario(*environment)
	case "decrypt":
		decryptScenario(*environment)
	case "show":
		showScenario(*environment)
	default:
		log.Print("Error: Undefined action '" + *action + "'")
	}
}
