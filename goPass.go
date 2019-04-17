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

type command struct {
	cmd      string
	abbrev   string
	function func([]string)
}
type commandHelp struct {
	cmd          string
	abbrev       string
	shorthelptxt string
	longhelptxt  string
}

var commands = []command{
	{cmd: "get", abbrev: "g", function: printPW},
	{cmd: "list", abbrev: "l", function: listPW},
	{cmd: "add", abbrev: "a", function: addPW},
	{cmd: "del", abbrev: "d", function: deletePW},
	{cmd: "settings", abbrev: "s", function: sett},
	{cmd: "help", abbrev: "h", function: help},
}
var commandsHelp = []commandHelp{
	{cmd: "get", abbrev: "g", shorthelptxt: "Get a password", longhelptxt: "get passwordname\n\nGets the password named passwordname from your passwords and prints it"},
	{cmd: "list", abbrev: "l", shorthelptxt: "Lists all passwords", longhelptxt: "list\n\nList all passwordnames you have saved in goPass"},
	{cmd: "add", abbrev: "a", shorthelptxt: "Add a password", longhelptxt: "add passwordname password\n\nAdds a password called passwordname with the value password"},
	{cmd: "del", abbrev: "d", shorthelptxt: "Delete a password", longhelptxt: "del passwordname\n\nDeletes the password called passwordname from goPass. A verification may be necessary"},
	{cmd: "settings", abbrev: "s", shorthelptxt: "Change or view the settings", longhelptxt: "settings setting [newValue]\n\nWhen no newValue is given it prints out the setting otherwise it sill change it. Possibe settings are askTwice and numWrongPW.\nFor more information call the function with the setting you want information for"},
	{cmd: "help", abbrev: "h", shorthelptxt: "Get help", longhelptxt: "help [command]\n\nGives you help. When no command is given it will print a short summary of all commands otherwise it will give specific information to the command"},
	{cmd: "end", abbrev: "e", shorthelptxt: "End goPass", longhelptxt: "end\n\nEnds goPass. Your passwords will all be saved after adding or deleting them so you can also close the console during goPass"},
}

var path = "./data.json"

var data dataStruct
var hashedPW string

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

		if splitIn[0] == "end" || splitIn[0] == "e" {
			return
		}
		commandExecuted := false
		for _, cmd := range commands {
			if splitIn[0] == cmd.cmd || splitIn[0] == cmd.abbrev {
				cmd.function(splitIn[1:])
				commandExecuted = true
				break
			}
		}
		if !commandExecuted {
			fmt.Println("I don´t know that command.")
		}

	}

}

//Manipulating the passwords
func printPW(args []string) {
	if len(args) == 0 {
		fmt.Println("Too few arguments:\n\tget password")
	}

	//Iterating over every argument
	for _, arg := range args {
		foundPW := false
		//Iterating over every known password
		for _, key := range data.Passwords {

			if string(decrypt([]byte(key.Name), hashedPW)) == arg {
				fmt.Println(arg, ":", string(decrypt([]byte(key.Password), hashedPW)))
				foundPW = true
				break
			}
		}
		if !foundPW {
			fmt.Println(arg, ": No such password")
		}

	}

}
func listPW(args []string) {
	//Iterating over every known password
	for _, key := range data.Passwords {
		fmt.Println(string(decrypt([]byte(key.Name), hashedPW)))
	}
}
func addPW(args []string) {

	if len(args) < 2 {
		fmt.Println("Too few arguments:\n\tadd passwordname password")
		return
	}
	if len(args) > 2 {
		fmt.Println("Too many arguments:\n\tadd passwordname password")
		return
	}
	var pw password

	pw.Name = encrypt([]byte(args[0]), hashedPW)
	if existPW([]byte(args[0])) {
		fmt.Println("A password with that name already exists")
		return
	}
	pw.Password = encrypt([]byte(args[1]), hashedPW)

	data.Passwords = append(data.Passwords, pw)

	err := saveData()

	if err != nil {
		fmt.Println("Something went wrong:", err)
		return
	}
	fmt.Println("New password saved")
}
func deletePW(args []string) {

	if len(args) == 0 {
		fmt.Println("Too few arguments:\n\tdel passwordname")
	}

	for _, pw := range args {
		if data.Settings.AskTwice {
			fmt.Println("Deleting password: ", pw)
			verify()
		}
		deletedPW := false
		//Iterating over every known password
		for index, key := range data.Passwords {
			if string(decrypt(key.Name, hashedPW)) == pw {
				//Delete password
				data.Passwords = append(data.Passwords[:index], data.Passwords[index+1:]...)

				deletedPW = true

				err := saveData()
				if err != nil {
					fmt.Println("Something went wrong")
					return
				}
				fmt.Println("Successfully deleted the password:", pw)
				break
			}
		}
		if !deletedPW {
			fmt.Println("No such password:", pw)
		}
	}

}

//Manipulate settings
func sett(args []string) {
	if len(args) < 1 {
		fmt.Println("Too few arguments:\n\tsettings setting [newValue]")
		return
	}
	if len(args) > 2 {
		fmt.Println("Too many arguments:\n\tsettings setting [newValue]")
		return
	}

	set := args[0]
	val := ""
	//Changing a setting
	if len(args) == 2 {
		val = args[1]
	}

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
	fmt.Println("Successfully changed the setting", set, "to", val)
}
func help(args []string) {
	if len(args) == 0 {
		for _, cmd := range commandsHelp {
			fmt.Printf("%s(%s): %s\n", cmd.cmd, cmd.abbrev, cmd.shorthelptxt)
		}
		return
	}
	for _, cmd := range commandsHelp {
		if cmd.cmd == args[0] || cmd.abbrev == args[0] {
			fmt.Printf("\n%s(%s):\n\t%s\n\n", cmd.cmd, cmd.abbrev, cmd.longhelptxt)
		}
	}
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
