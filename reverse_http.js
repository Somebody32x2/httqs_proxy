// https://medium.com/@nimit95/a-simple-http-https-proxy-in-node-js-4eb0444f38fc
const net = require('net');
const crypto = require("crypto");
const kyber = require('crystals-kyber');

const server = net.createServer()

class Client {
    constructor() {
        this.state = "UNKNOWN"
    }
    initalize() {
        while (true) {
            this.id = crypto.randomUUID();
            if (!clients[this.id]) break;
        }
        this.state = "SUPPORTED"
        let keys = kyber.KeyGen768();
        this.publicKey = keys[0];
        this.symmetricKey = keys[1];
        this.lastUsed = Date.now()
        this.created = Date.now()
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
    // console.log('Client Connected To Proxy');
    // We need only the data once, the starting packet
    clientToProxySocket.on('data', (data) => {
        console.log(data.toString())
        if (data.toString().includes("HTTQS-HELLO")) {
            clientToProxySocket.client.initalize()
            clientToProxySocket.write("HTTQS-PK:" + JSON.stringify(clientToProxySocket.client.publicKey) + "\r\n") // TODO: Use hex, b64, or raw instead of JSON string
        } else if (clientToProxySocket.client.state === "SUPPORTED" && data.toString().includes("HTTQS-HANDSHAKE-MESSAGE:")) {
            clientToProxySocket.client.shared_secret = kyber.Decrypt768(data.toString().split("HTTQS-HANDSHAKE-MESSAGE:")[1], clientToProxySocket.client.symmetricKey)
            clientToProxySocket.client.state = "READY"
            clientToProxySocket.client.iv = crypto.getRandomValues(new Uint8Array(16));
            clientToProxySocket.client.key = crypto.subtle.importKey("raw", clientToProxySocket.client.shared_secret, "AES-GCM", true, ["encrypt", "decrypt"])
            clientToProxySocket.client.lastUsed = Date.now()
            clientToProxySocket.write("HTTQS-IV:" + Object.values(clientToProxySocket.client.iv).join(",") + "\r\n"); // TODO: Use hex, b64, or raw instead of JSON string
        }
            // let isTLSConnection = data.toString().indexOf('CONNECT') !== -1;
            // // console.log(data.toString())
            //
            // // Considering Port as 80 by default
            // let serverPort = 80;
            // let serverAddress;
            // if (isTLSConnection) {
            //     // Port changed to 443, parsing the host from CONNECT
            //     serverPort = 443;
            //     serverAddress = data.toString()
            //         .split('CONNECT ')[1]
            //         .split(' ')[0];
            //     // Parse and remove the port number
            //     if (serverAddress.indexOf(':') !== -1) {
            //         serverPort = serverAddress.split(':')[1];
            //         serverAddress = serverAddress.split(':')[0];
            //     }
            // } else {
            //     // Parsing HOST from HTTP
            //     serverAddress = data.toString()
            //         .split('Host: ')[1].split('\r\n')[0];
            //     // Parse the port number if specified
            //     if (serverAddress.indexOf(':') !== -1) {
            //         serverPort = serverAddress.split(':')[1];
            //         serverAddress = serverAddress.split(':')[0];
            //     }
            // }
            // console.log(`Connecting to ${serverAddress}:${serverPort}`)
            // let proxyToServerSocket = net.createConnection({
            //     host: serverAddress,
            //     port: serverPort
            // }, () => {
            //     // console.log('PROXY TO SERVER SET UP');
            //     // console.log(serverAddress)
            //     if (isTLSConnection) {
            //         //Send Back OK to HTTPS CONNECT Request
            //         clientToProxySocket.write('HTTP/1.1 200 OK\r\n\n');
            //     } else {
            //         proxyToServerSocket.write(data);
            //     }
            //     // Piping the sockets
            //     clientToProxySocket.pipe(proxyToServerSocket);
            //     proxyToServerSocket.pipe(clientToProxySocket);
            //
            //     proxyToServerSocket.on('error', (err) => {
            //         console.log('PROXY TO SERVER ERROR');
            //         console.log(err);
            //     });
            // });
            // clientToProxySocket.on('error', err => {
            //     console.log('CLIENT TO PROXY ERROR');
            //     console.log(err);
            // });
    });
});