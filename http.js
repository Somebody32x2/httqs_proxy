// https://medium.com/@nimit95/a-simple-http-https-proxy-in-node-js-4eb0444f38fc
const net = require('net');
const crypto = require("crypto");
const kyber = require('crystals-kyber');

const server = net.createServer();
const IV_U8_LABEL = new TextEncoder().encode("HTTQS-IV:");
const PK_U8_LABEL = new TextEncoder().encode("HTTQS-PK:");
const MESSAGE_U8_LABEL = new TextEncoder().encode("HTTQS-HANDSHAKE-MESSAGE:");

const MTU = 14000;

let knownUnsupportingServers = [];

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
server.listen(8888, () => {
    console.log('Server running at http://localhost:' + 8888);
});
server.on('connection', (clientToProxySocket) => {
    // console.log('Client Connected To Proxy');
    // We need only the data once, the starting packet


    clientToProxySocket.once('data', (clientData) => {
        let isTLSConnection = clientData.toString().indexOf('CONNECT') !== -1;
        // console.log(data.toString())

        // Considering Port as 80 by default
        let serverPort = 80;
        let serverAddress;
        if (isTLSConnection) {
            // Port changed to 443, parsing the host from CONNECT
            serverPort = 443;
            serverAddress = clientData.toString()
                .split('CONNECT ')[1]
                .split(' ')[0];
            // Parse and remove the port number
            if (serverAddress.indexOf(':') !== -1) {
                serverPort = serverAddress.split(':')[1];
                serverAddress = serverAddress.split(':')[0];
            }
        } else {
            // Parsing HOST from HTTP
            serverAddress = clientData.toString()
                .split('Host: ')[1].split('\r\n')[0];
            // Parse the port number if specified
            if (serverAddress.indexOf(':') !== -1) {
                serverPort = serverAddress.split(':')[1];
                serverAddress = serverAddress.split(':')[0];
            }
        }
        console.log(`Connecting to ${serverAddress}:${serverPort}`)



        let proxyToHttqsSocket = net.createConnection({
            host: serverAddress, port: 8889
        });
        proxyToHttqsSocket.client = {state: "UNKNOWN"}
        proxyToHttqsSocket.on('error', (data) => {
            // console.log(data.toString())
            console.log(`${serverAddress}:${serverPort} does not support HTTQS (${data.toString()})`);
            httqsUnsupported();
        });
        proxyToHttqsSocket.on("connect", () => {
            proxyToHttqsSocket.write("HTTQS-HELLO")
        });
        proxyToHttqsSocket.on("data", async (data) => {
            console.log("GOT DATA FROM PROXY (likely encrypted)" + data.toString().slice(0, 10) + "... (" + data.toString().length + " bytes)\n");
            if (data.slice(0, PK_U8_LABEL.byteLength).equals(PK_U8_LABEL)) {
                let pk = new Uint8Array(data.slice(PK_U8_LABEL.byteLength));
                let [c, ss] = kyber.Encrypt768(pk);
                proxyToHttqsSocket.client.shared_secret = ss;

                // console.dir({shared_secret: proxyToHttqsSocket.client.shared_secret})

                proxyToHttqsSocket.client.state = "SUPPORTED"

                // console.dir({handshake_message: JSON.stringify(c)})
                let u8Message = new Uint8Array(c.length + MESSAGE_U8_LABEL.byteLength);
                u8Message.set(MESSAGE_U8_LABEL, 0);
                u8Message.set(c, MESSAGE_U8_LABEL.byteLength);
                proxyToHttqsSocket.write(u8Message);

            } else if (data.toString().includes("HTTQS-IV:")) {
                let iv = new Uint8Array(16);
                data.copy(iv, 0, IV_U8_LABEL.byteLength);
                proxyToHttqsSocket.client.iv = iv;
                proxyToHttqsSocket.client.key = await crypto.subtle.importKey("raw", proxyToHttqsSocket.client.shared_secret, "AES-GCM", true, ["encrypt", "decrypt"]);
                proxyToHttqsSocket.client.state = "READY";
                proxyToHttqsSocket.client.lastUsed = Date.now();

                console.log(`${serverAddress}:${serverPort} COMPLETED HTTQS HANDSHAKE`);
                // clientToProxySocket.dataHandler = HTTQS_DATA_HANDLER;
                async function handleClientHTTQSData(data) {
                    console.log("GOT HTTQS CLIENT DATA; ENCRYPTING BYTES: " + data.toString());
                    let encrypted = await crypto.subtle.encrypt({
                        name: "AES-GCM", iv: proxyToHttqsSocket.client.iv
                    }, proxyToHttqsSocket.client.key, data);
                    proxyToHttqsSocket.write(new Uint8Array(encrypted));
                    // console.dir({iv: proxyToHttqsSocket.client.iv, key: await crypto.subtle.exportKey("jwk",proxyToHttqsSocket.client.key), data: encrypted})
                }

                if (!isTLSConnection) {
                    handleClientHTTQSData(clientData)
                }
                clientToProxySocket.on("data", handleClientHTTQSData);

            } else if (proxyToHttqsSocket.client.state === "READY") {
                console.dir({
                    iv: proxyToHttqsSocket.client.iv,
                    key: await crypto.subtle.exportKey("jwk", proxyToHttqsSocket.client.key),
                    data: data
                })
                console.log("GOT HTTQS SERVER DATA; DECRYPTING BYTES");
                let decrypted = await crypto.subtle.decrypt({
                    name: "AES-GCM", iv: proxyToHttqsSocket.client.iv
                }, proxyToHttqsSocket.client.key, data);
                console.log("DECRYPTED BYTES: " + decrypted.toString());
                clientToProxySocket.write(new Uint8Array(decrypted));
            }
        });

        clientToProxySocket.on("close", () => {
            proxyToHttqsSocket.destroy();
            console.log("Closing HTTQS connection to " + serverAddress + ":" + serverPort);
        });

        function httqsUnsupported() {

            let proxyToServerSocket = net.createConnection({
                host: serverAddress, port: serverPort
            }, () => {
                // console.log('PROXY TO SERVER SET UP');
                // console.log(serverAddress)
                if (isTLSConnection) {
                    //Send Back OK to HTTPS CONNECT Request
                    clientToProxySocket.write('HTTP/1.1 200 OK\r\n\n');
                } else {
                    proxyToServerSocket.write(clientData);
                }
                // Piping the sockets
                clientToProxySocket.pipe(proxyToServerSocket);
                proxyToServerSocket.pipe(clientToProxySocket);

                proxyToServerSocket.on('error', (err) => {
                    console.log(`Error from server ${serverAddress}:${serverPort} : ${err}`);
                });
            });
        }

        clientToProxySocket.on('error', err => {
            console.log(`Error from local client: ${err}`);
        });
    });
});