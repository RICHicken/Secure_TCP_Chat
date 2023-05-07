# Secure TCP Chat
## About

This is a simple TCP chat program where clients can connect to a server. Messages are encrypted using RSA encryption. **This was a small side project, and most likely will not be maintained.**

## How to use
This *should* be able to build to any platform supported by go, I know it works on Windows and Linux.

### Server
1. You will be prompted to specify a port number.
2. After a valid port has been given, You will be prompted to specify the maximum number of characters allowed.
3. After a valid number has been given, the server should be up and running on `localhost:{port}}`

### Client
1. You will be prompted to type an IP.
2. Once the program is able to find the server, the server will prompt you for a username.
3. Type a name, and you will be connected.