// https://medium.com/@nimit95/a-simple-http-https-proxy-in-node-js-4eb0444f38fc
const net = require('net');
const crypto = require("crypto");
const kyber = require('crystals-kyber');

const server = net.createServer()
const IV_U8_LABEL = new TextEncoder().encode("HTTQS-IV:");
const PK_U8_LABEL = new TextEncoder().encode("HTTQS-PK:");
const MESSAGE_U8_LABEL = new TextEncoder().encode("HTTQS-HANDSHAKE-MESSAGE:");

const MTU = 14000;

let socketId = 0;

class Client {
    constructor() {
        this.state = "UNKNOWN"
    }

    initalize() {
        this.state = "SUPPORTED"
        let keys = kyber.KeyGen768();
        this.publicKey = keys[0];
        this.symmetricKey = keys[1];
    }
}

server.on('connection', (clientToProxySocket) => {
    // console.log('Client Connected To Proxy');
});
server.on('error', (err) => {
    console.log('SERVER ERROR');
    console.log(err);
});
server.on('close', () => {
    // console.log('Client Disconnected');
});
server.listen(8889, () => {
    console.log('Server running at http://localhost:' + 8889);
});
server.on('connection', (clientToProxySocket) => {
    clientToProxySocket.client = new Client();
    let proxyToServerSocket = undefined;
    clientToProxySocket.id = socketId++;
    clientToProxySocket.on('data', async (data) => {
        console.log("RECIEVED DATA FROM CLIENT:" + data.toString().slice(0, 40) + "... (" + data.toString().length + " bytes)" + `(C${clientToProxySocket.id})`);
        if (data.toString().includes("HTTQS-HELLO")) {
            // This is a client that supports HTTQS, get ready to set up encryption using Kyber768
            clientToProxySocket.client.initalize()

            // Write the public key to the client in raw bytes
            let u8Pk = new Uint8Array(clientToProxySocket.client.publicKey.length + PK_U8_LABEL.byteLength);
            u8Pk.set(PK_U8_LABEL, 0);
            u8Pk.set(clientToProxySocket.client.publicKey, PK_U8_LABEL.byteLength);
            clientToProxySocket.write(u8Pk);

        } else if (clientToProxySocket.client.state === "SUPPORTED" && data.slice(0, MESSAGE_U8_LABEL.byteLength).equals(MESSAGE_U8_LABEL)) {
            // We have received the handshake message, which we can use to derive the shared secret
            clientToProxySocket.client.shared_secret = kyber.Decrypt768(Array.from(new Uint8Array(data.slice(MESSAGE_U8_LABEL.byteLength))), clientToProxySocket.client.symmetricKey)
            clientToProxySocket.client.state = "READY"
            clientToProxySocket.client.iv = crypto.getRandomValues(new Uint8Array(16));
            // console.dir({shared_secret: clientToProxySocket.client.shared_secret})
            // Use the shared secret to derive the bulk encryption (AES) key
            clientToProxySocket.client.key = await crypto.subtle.importKey("raw", clientToProxySocket.client.shared_secret, "AES-GCM", true, ["encrypt", "decrypt"])

            // Write the IV to the client in raw bytes
            let u8Message = new Uint8Array(clientToProxySocket.client.iv.byteLength + IV_U8_LABEL.byteLength);
            u8Message.set(IV_U8_LABEL, 0);
            u8Message.set(clientToProxySocket.client.iv, IV_U8_LABEL.byteLength);
            clientToProxySocket.write(u8Message);

            console.log(`COMPLETED HTTQS HANDSHAKE (C${clientToProxySocket.id})`);

        } else if (clientToProxySocket.client.state === "READY") {
            // console.dir({iv: clientToProxySocket.client.iv, key: await crypto.subtle.exportKey("jwk", clientToProxySocket.client.key), data: data})
            let decrypted = await crypto.subtle.decrypt({
                name: "AES-GCM", iv: clientToProxySocket.client.iv
            }, clientToProxySocket.client.key, data);
            console.log("DECRYPTED BYTES: " + new TextDecoder().decode(decrypted).slice(0, 40) + "... (" + decrypted.toString().length + " bytes) (C" + clientToProxySocket.id + ")\n");

            if (!proxyToServerSocket) {
                // First time; connect to the server using the decrypted data (this is likely this same server but with a different port)
                let clientData = Buffer.from(decrypted)
                let clientReqString = clientData.toString();
                let isTLSConnection = clientReqString.indexOf('CONNECT') !== -1;

                // Considering Port as 80 by default
                let serverPort = 80;
                let serverAddress;
                if (isTLSConnection) {
                    // Port changed to 443, parsing the host from CONNECT
                    serverPort = 443;
                    serverAddress = clientReqString
                        .split('CONNECT ')[1]
                        .split(' ')[0];
                    // Parse and remove the port number
                    if (serverAddress.indexOf(':') !== -1) {
                        serverPort = serverAddress.split(':')[1];
                        serverAddress = serverAddress.split(':')[0];
                    }
                } else {
                    // Parsing HOST from HTTP
                    serverAddress = clientReqString
                        .split('Host: ')[1].split('\r\n')[0];
                    // Parse the port number if specified
                    if (serverAddress.indexOf(':') !== -1) {
                        serverPort = serverAddress.split(':')[1];
                        serverAddress = serverAddress.split(':')[0];
                    }
                }
                console.log(`Connecting to ${serverAddress}:${serverPort} (C${clientToProxySocket.id})`)
                proxyToServerSocket = net.createConnection({
                    host: serverAddress, port: serverPort
                }, async () => {
                    if (isTLSConnection) {
                        // Send Back OK to HTTPS CONNECT Request
                        let res = "HTTP/1.1 200 OK\r\n\n";
                        let encrypted = await crypto.subtle.encrypt({
                            name: "AES-GCM", iv: clientToProxySocket.client.iv
                        }, clientToProxySocket.client.key, Buffer.from(res));
                        clientToProxySocket.write(new Uint8Array(encrypted));
                        console.log("SENT OK TO CLIENT");
                        console.dir({
                            iv: clientToProxySocket.client.iv,
                            key: await crypto.subtle.exportKey("jwk", clientToProxySocket.client.key),
                            data: new Uint8Array(encrypted)
                        });
                    } else {
                        proxyToServerSocket.write(clientData);
                    }

                    proxyToServerSocket.on('error', (err) => {
                        console.log(`Error from server ${serverAddress}:${serverPort} : ${err} (C${clientToProxySocket.id})`);
                    });

                    // On receiving data from the server send it to the client encrypted
                    proxyToServerSocket.on('data', async (data) => {
                        console.log("GOT SERVER DATA; ENCRYPTING BYTES: " + data.toString().slice(0, 40) + "... (" + data.toString().length + " bytes) (C" + clientToProxySocket.id + ")\n");
                        for (let i = 0; i < data.length; i += MTU) {
                            let encrypted = await crypto.subtle.encrypt({
                                name: "AES-GCM", iv: clientToProxySocket.client.iv
                            }, clientToProxySocket.client.key, data.slice(0, MTU));
                            data = data.slice(MTU);
                            console.dir({
                                iv: clientToProxySocket.client.iv,
                                key: await crypto.subtle.exportKey("jwk", clientToProxySocket.client.key),
                                data: new Uint8Array(encrypted),
                                client: clientToProxySocket.id,
                            })
                            clientToProxySocket.write(new Uint8Array(encrypted));
                        }
                    });
                });
            } else {
                // Already connected to the server, just write the decrypted data
                console.log(`SENDING DECRTYPTED DATA TO SERVER (C${clientToProxySocket.id})`);
                proxyToServerSocket.write(new Uint8Array(decrypted));
            }
            // clientToProxySocket.write(new Uint8Array(decrypted));
        }
    });
    clientToProxySocket.on('error', (err) => {
        console.log('CLIENT ERROR');
        console.log(err);
    });
});