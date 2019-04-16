package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

var lock sync.Mutex
var marshal = func(v interface{}) (io.Reader, error) {
	b, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}
var unmarshal = func(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

var reader = bufio.NewReader(os.Stdin)

type dataStruct struct {
	PWHashHash string
	Passwords  []password
	Settings   settings
}
type password struct {
	Name     []byte
	Password []byte
}
type settings struct {
	AskTwice   bool
	NumWrongPW int
}

var path = "./data.json"

var data dataStruct
var hashedPW string
var cryptKey string

func main() {

	//Load the data from data.json
	if err := loadData(); err != nil {
		log.Fatalln(err)
	}

	//Checking if User has password
	if data.PWHashHash != "" {
		//User has password, logging in using password
		verify()

	} else {
		//User has no password, setting up password
		fmt.Println("You do not have a password. Please enter a password.")
		hashedPW = createHash(getPassword())
		data.PWHashHash = createHash(hashedPW)

		//Initial settings
		data.Settings.AskTwice = true
		data.Settings.NumWrongPW = 3

		if err := saveData(); err != nil {
			log.Fatalln(err)
		}
	}
	for true {
		//Reacting to input by the user
		input := getInput(">")
		splitIn := strings.Split(input, " ")

		switch splitIn[0] {
		case "get":
			if len(splitIn) == 1 {
				fmt.Println("Missing argument: Password to print")
				break
			}
			printPW(splitIn[1])
			break
		case "list":
			listPW()
			break
		case "add":
			addPW()
			break
		case "del":
			if len(splitIn) == 1 {
				fmt.Println("Missing argument: Password to delete")
				break
			}
			deletePW(splitIn[1])
			break
		case "settings":
			if len(splitIn) == 1 {
				fmt.Println("Missing argument: Setting to display (e.g. askTwice, numWrongPW); Not required argument: Value to change the setting to")
				break
			}
			if len(splitIn) == 2 {
				sett(splitIn[1], "")
				break
			}
			sett(splitIn[1], splitIn[2])
		case "end":
			return
		default:
			fmt.Println("I don´t know this command.")
			break
		}
	}

}

//Manipulating the passwords
func printPW(pw string) {
	//Iterating over every known password
	for _, key := range data.Passwords {
		if string(decrypt([]byte(key.Name), hashedPW)) == pw {
			fmt.Println(string(decrypt([]byte(key.Password), hashedPW)))
			return
		}
	}
	fmt.Println("No such password")
}
func listPW() {
	//Iterating over every known password
	for _, key := range data.Passwords {
		fmt.Println(string(decrypt([]byte(key.Name), hashedPW)))
	}
}
func addPW() {
	var pw password

	rawName := getInput("Name: ")
	pw.Name = encrypt([]byte(rawName), hashedPW)
	if existPW([]byte(rawName)) {
		fmt.Println("A password with that name already exists")
		return
	}
	pw.Password = encrypt([]byte(getInput("Password : ")), hashedPW)

	data.Passwords = append(data.Passwords, pw)

	err := saveData()

	if err != nil {
		fmt.Println("Something went wrong")
		return
	}
	fmt.Println("New password saved")
}
func deletePW(pw string) {
	if data.Settings.AskTwice {
		verify()
	}
	//Iterating over every known password
	for index, key := range data.Passwords {
		if string(decrypt(key.Name, hashedPW)) == pw {
			//Delete password
			data.Passwords = append(data.Passwords[:index], data.Passwords[index+1:]...)

			err := saveData()
			if err != nil {
				fmt.Println("Something went wrong")
				return
			}
			fmt.Println("Successfully deleted the password")
			return
		}
	}

	fmt.Println("No such password")

}

//Manipulate settings
func sett(set, val string) {
	switch set {
	case "askTwice":
		switch val {
		case "true":
			data.Settings.AskTwice = true
			break
		case "false":
			data.Settings.AskTwice = false
			break
		default:
			fmt.Println("Ask twice before deleting something:", data.Settings.AskTwice)
			return
		}
		break
	case "numWrongPW":
		i, err := strconv.Atoi(val)
		if err == nil {
			data.Settings.NumWrongPW = i
			break
		}
		fmt.Println("Number of wrong passwords you can type in before being kicked out (nagative for no maximum):", data.Settings.NumWrongPW)
		return
	}

	err := saveData()

	if err != nil {
		fmt.Println("Something went wrong")
	}
	fmt.Println("Successfully changed the settings")
}

//Helper function for addPW to know if a PW with that name already exists
func existPW(pw []byte) bool {
	//Iterating over every known password
	for _, key := range data.Passwords {
		if string(decrypt(key.Name, hashedPW)) == string(pw) {
			return true
		}
	}
	return false
}

//Verifying the password the user typed in is correct
func verify() {
	wrongPW := 0
	hashedPW = createHash(getPassword())
	hashedGivenPW := createHash(hashedPW)
	for hashedGivenPW != data.PWHashHash {
		fmt.Println("You got the wrong password, try again")
		wrongPW++
		if wrongPW == data.Settings.NumWrongPW {
			fmt.Println("You got the wrong password too often")
			os.Exit(0)
		}
		hashedPW = createHash(getPassword())
		hashedGivenPW = createHash(hashedPW)
	}

}

//Cryptography from https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/
func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

//Getting different kinds of inputs
func getInput(prefix string) string {
	fmt.Print(prefix)
	text, _ := reader.ReadString('\n')
	//Deleting the end of the line
	text = strings.Replace(text, "\r\n", "", -1)
	return text
}

func getPassword() string {
	fmt.Print("Password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(bytePassword)
}

//Loading and storing the data
func loadData() error {
	lock.Lock()
	defer lock.Unlock()
	f, err := os.Open(path)
	if err != nil {
		//No such file
		f, err = os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return nil
	}
	defer f.Close()
	return unmarshal(f, &data)
}

func saveData() error {
	lock.Lock()
	defer lock.Unlock()

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := marshal(data)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, r)
	return err
}
