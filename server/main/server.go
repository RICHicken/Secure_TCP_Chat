package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	SERVER_HOST = "localhost"
	SERVER_PORT = "9988"
	SERVER_TYPE = "tcp"
	BUFFER_SIZE = 1024
)

type connectionInfo struct {
	key  *rsa.PublicKey
	name string
}

var mutex sync.Mutex
var connections map[*net.Conn]connectionInfo

var privateKey *rsa.PrivateKey
var publicKey rsa.PublicKey

var msgLenStr string

func main() {
	fmt.Println("Performing Setup...")
	connections = make(map[*net.Conn]connectionInfo)
	var err error = nil
	var msgLen int = 0

	for err != nil || msgLen <= 1 {
		fmt.Print("Type Max Message Length: ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			msgLenStr = scanner.Text()
		}

		msgLen, err = strconv.Atoi(msgLenStr)
	}

	// Generate a private key
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	publicKey = privateKey.PublicKey

	fmt.Println("Server Running...")
	// Create server
	server, err := net.Listen(SERVER_TYPE, SERVER_HOST+":"+SERVER_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	defer server.Close()

	fmt.Println("Listening on " + SERVER_HOST + ":" + SERVER_PORT)
	fmt.Println("Waiting for client...")

	// Check for connections
	for {
		connection, err := server.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		fmt.Println("client connected")

		// Make a new thread for each connection
		go handleClient(connection)
	}
}

func handleClient(connection net.Conn) {
	buffer := make([]byte, BUFFER_SIZE)

	defer removeConnection(&connection)
	defer connection.Close()
	defer fmt.Println("Connection closed")

	// Send max size
	sendMessage(&connection, msgLenStr)

	// Manage Keys
	key := receiveKey(&connection, buffer)
	sendPublicKey(&connection)

	if key == nil {
		return
	}

	// Ask user for name
	sendMessage(&connection, string(encrypt(key, []byte("What is your name?"))))

	rawmessage, _, ret := receiveMessage(&connection, buffer)

	if ret {
		return
	}

	fmt.Println("Received name: ", rawmessage)
	message := string(decrypt([]byte(rawmessage)))

	// Add connection after because we don't want to send them other user's messages until they say their name.
	addConnection(&connection, message, key)

	// Allow the user to write messages
	for {
		message, _, ret = receiveMessage(&connection, buffer)

		if ret {
			return
		}

		fmt.Println("\nRECIEVED: ", message)
		messageString := connections[&connection].name + ": " + string(decrypt([]byte(message)))
		fmt.Println("\nPrepared Message - " + messageString)
		broadcast(messageString, &connection)
	}
}

func addConnection(connection *net.Conn, name string, key *rsa.PublicKey) {
	mutex.Lock()
	fmt.Println("\nADDING CONNECTION:", name, key)
	connections[connection] = connectionInfo{name: name, key: key}
	mutex.Unlock()
}

func removeConnection(connection *net.Conn) {
	mutex.Lock()
	fmt.Println("\nREMOVING CONNECTION", connection)
	delete(connections, connection)
	mutex.Unlock()
}

func broadcast(message string, sender *net.Conn) {
	mutex.Lock()
	for connection, _ := range connections {

		if connection == sender {
			continue
		}

		sendMessage(connection, string(encrypt(connections[connection].key, []byte(message))))
	}
	mutex.Unlock()
}

func sendPublicKey(connection *net.Conn) {
	sendMessage(connection, string(x509.MarshalPKCS1PublicKey(&publicKey)))
}

func receiveKey(connection *net.Conn, buffer []byte) *rsa.PublicKey {
	pubKey, _, _ := receiveMessage(connection, buffer)

	key, err := x509.ParsePKCS1PublicKey([]byte(pubKey))

	if err != nil {
		return nil
	}

	return key
}

// Receives a message from the server
func receiveMessage(connection *net.Conn, buffer []byte) (string, int, bool) {
	message := ""
	bytesRead := 0
	var expectedBytes int

	mLen, err := (*connection).Read(buffer)
	if err != nil {
		if err == io.EOF || err == net.ErrClosed {
			fmt.Println("Client closed the connection")
			return "", 0, true
		}
		fmt.Println("Error reading:", err.Error())
		return "", 0, true
	}

	// Get the number of expected bytes (at the beginning of the message)
	numberSection := string(buffer[:strings.Index(string(buffer), "|")])
	expectedBytes, err = strconv.Atoi(numberSection)

	if err != nil {
		return "Could not receive message.", 26, true
	}

	bytesRead -= len(numberSection) + 1
	message += string(buffer[strings.Index(string(buffer), "|")+1 : mLen])
	bytesRead += mLen

	// Keep reading until we get the whole message
	for bytesRead < expectedBytes {
		mLen, err = (*connection).Read(buffer)
		if err != nil {
			fmt.Println("Error reading:", err.Error())
			mLen = 0
		}

		message += string(buffer[:mLen])
		bytesRead += mLen
	}

	return message, bytesRead, false
}

func sendMessage(connection *net.Conn, message string) {
	fmt.Println("SENDING", strconv.Itoa(len(message))+"|"+message+"\n")
	_, err := (*connection).Write([]byte(strconv.Itoa(len(message)) + "|" + message))
	if err != nil {
		fmt.Println("Error writing:", err.Error())
	}
}

func encrypt(key *rsa.PublicKey, message []byte) []byte {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		key,
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
