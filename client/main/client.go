package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/eiannone/keyboard"
)

const (
	SERVER_HOST = "localhost"
	SERVER_PORT = "9988"
	SERVER_TYPE = "tcp"
	BUFFER_SIZE = 1024
)

var mutex sync.Mutex
var server net.Conn
var buffer []byte
var messageBuf []rune

var mBufPos int

var privateKey *rsa.PrivateKey
var publicKey rsa.PublicKey

var serverKey *rsa.PublicKey

var maxMsgSize int
var name string

func main() {
	var err error
	var serverIP string

	fmt.Print("Type IP: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		serverIP = scanner.Text()
	}

	server, err = net.Dial(SERVER_TYPE, serverIP)

	for err != nil {
		fmt.Print("Could not connect to server. Try again: ")
		if scanner.Scan() {
			serverIP = scanner.Text()
		}
		server, err = net.Dial(SERVER_TYPE, serverIP)
	}

	// server, err = net.Dial(SERVER_TYPE, SERVER_HOST+":"+SERVER_PORT)

	buffer = make([]byte, BUFFER_SIZE)

	// Recieve max buffer size (not encrypted)
	recv, _ := receiveMessage()
	maxMsgSize, err = strconv.Atoi(recv)

	if err != nil {
		panic(err)
	}

	fmt.Println("Maximum Message length is:", maxMsgSize)

	messageBuf = make([]rune, maxMsgSize)

	if err != nil {
		panic(err)
	}

	// Generate a private key
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	publicKey = privateKey.PublicKey

	var inText string

	defer server.Close()

	sendPublicKey()
	receiveKey()
	go receiveAndPrint()

	// Server should ask for name
	// Send name to server
	scanner = bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		inText = scanner.Text()
	}
	sendMessage(string(encrypt([]byte(inText))))

	// Save name in local buffer
	name = inText + ": "

	// Now set up, time for messaging

	// Create keyboard event
	if err := keyboard.Open(); err != nil {
		panic(err)
	}
	defer func() {
		_ = keyboard.Close()
	}()

	// Infinite messaging loop
	var char rune
	var key keyboard.Key

	for {
		fmt.Print(name)

		key = keyboard.KeyCtrlSpace
		// Stay in this loop while user is typing message
		for key != keyboard.KeyEnter {
			char, key, err = keyboard.GetKey()
			if err != nil {
				continue
			}

			// Lock since we are printing
			mutex.Lock()
			switch key {
			case 0:
				if mBufPos < maxMsgSize {
					fmt.Print(string(char))
					messageBuf[mBufPos] = char
					mBufPos++
				}
			case keyboard.KeyBackspace:
				fallthrough
			case keyboard.KeyBackspace2:
				if mBufPos > 0 {
					mBufPos--
					fmt.Print(string("\b \b"))
				}
			case keyboard.KeySpace:
				if mBufPos < maxMsgSize {
					messageBuf[mBufPos] = ' '
					fmt.Print(" ")
					mBufPos++
				}
			}
			mutex.Unlock()
		}

		// At this point, the user pushed enter

		// What...
		sendMessage(string(encrypt([]byte(string(messageBuf[:mBufPos])))))
		// sendMessage(string(string(messageBuf[bufStart:mBufPos])))

		// print newline because we pushed enter
		fmt.Println()

		mBufPos = 0

	}

}

// Prints the received message
func receiveAndPrint() {

	// Wait for server to ask for name
	rawmessage, _ := receiveMessage()

	message := string(decrypt([]byte(rawmessage)))

	fmt.Println("\r" + message)

	for {
		// When we get a message
		rawmessage, mLen := receiveMessage()
		message := string(decrypt([]byte(rawmessage)))
		mutex.Lock()

		// Print the message
		fmt.Print("\r" + message)

		// Clear any extra part of the line
		if mLen < mBufPos {
			fmt.Print(strings.Repeat(" ", mBufPos-mLen))
		}

		fmt.Println()

		// Reprint our unfinished message
		fmt.Print("\r" + name + string(messageBuf[:mBufPos]))
		mutex.Unlock()

	}
}

// Receives a message from the server
func receiveMessage() (string, int) {
	message := ""
	bytesRead := 0
	var expectedBytes int

	mLen, err := server.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
		mLen = 0
	}

	// Get the number of expected bytes (at the beginning of the message)
	numberSection := string(buffer[:strings.Index(string(buffer), "|")])
	expectedBytes, err = strconv.Atoi(numberSection)

	if err != nil {
		return "Could not receive message.", 26
	}

	bytesRead -= len(numberSection) + 1
	message += string(buffer[strings.Index(string(buffer), "|")+1 : mLen])
	bytesRead += mLen

	// Keep reading until we get the whole message
	for bytesRead < expectedBytes {
		mLen, err = server.Read(buffer)
		if err != nil {
			fmt.Println("Error reading:", err.Error())
			mLen = 0
		}

		message += string(buffer[:mLen])
		bytesRead += mLen
	}

	return message, bytesRead
}

func sendMessage(message string) {
	_, err := server.Write([]byte(strconv.Itoa(len(message)) + "|" + message))
	if err != nil {
		fmt.Println("Error writing:", err.Error())
	}
}

func encrypt(message []byte) []byte {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		serverKey,
		message,
		nil)
	if err != nil {
		panic(err)
	}

	return encryptedBytes
}

func decrypt(encryptedBytes []byte) []byte {
	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	return decryptedBytes
}

func sendPublicKey() {
	sendMessage(string(x509.MarshalPKCS1PublicKey(&publicKey)))
}

func receiveKey() {

	pubKey, _ := receiveMessage()

	var err error
	serverKey, err = x509.ParsePKCS1PublicKey([]byte(pubKey))

	if err != nil {
		panic(err)
	}
}
