package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"regexp"

	"go.mongodb.org/mongo-driver/bson"
)

// Manager handles request keys
type Manager struct {
	validKeys        map[string]string
	config           *tls.Config
	caPool           *x509.CertPool
	mongoHost        string
	tenantCertFolder string
}

// RegisterArgs are necessary
type RegisterArgs struct {
	Key, TenantID string
}

// Register does something cool
func (m *Manager) Register(args RegisterArgs, reply *string) error {
	fmt.Println("Registering key", args.Key)
	fmt.Println("To tenant", args.TenantID)

	m.validKeys[args.Key] = args.TenantID
	*reply = "OK"
	return nil
}

// Unregister does something not very cool
func (m *Manager) Unregister(key string, reply *string) error {
	fmt.Println("Unregistering key", key)
	delete(m.validKeys, key)
	*reply = "OK"
	return nil
}

var keyFromHostExp = regexp.MustCompile(`^([^\.]+)\.mongo\.localhost$`)

func handleMongoClient(m *Manager, con net.Conn, host string) {
	defer con.Close()

	if !keyFromHostExp.MatchString(host) {
		fmt.Println("Could not match host regex")
		return
	}

	key := keyFromHostExp.FindStringSubmatch(host)[1]
	if tenant, ok := m.validKeys[key]; !ok {
		fmt.Println("Key", key, "is not valid")
	} else {
		clientcert, err := tls.LoadX509KeyPair(m.tenantCertFolder+tenant+".cert.pem", m.tenantCertFolder+tenant+".key.pem")
		if err != nil {
			fmt.Println("Error reading client cert", err)
			return
		}

		config := tls.Config{
			RootCAs:      m.caPool,
			Certificates: []tls.Certificate{clientcert},
		}
		serverCon, err := tls.Dial("tcp", m.mongoHost, &config)
		if err != nil {
			fmt.Println("Error dialing", err)
			return
		}

		parsedCert, err := x509.ParseCertificate(clientcert.Certificate[0])
		authBSON, err := bson.Marshal(bson.D{{"authenticate", 1}, {"mechanism", "MONGODB-X509"}, {"user", parsedCert.Subject.String()}, {"$db", "$external"}})
		authMsg := make([]byte, 21, len(authBSON)+21)

		binary.LittleEndian.PutUint32(authMsg[0:], uint32(len(authBSON)+21)) // Length
		binary.LittleEndian.PutUint32(authMsg[4:], 1)                        // RequestID
		binary.LittleEndian.PutUint32(authMsg[8:], 1)                        // ResponseTo
		binary.LittleEndian.PutUint32(authMsg[12:], 2013)                    // Opcode
		binary.LittleEndian.PutUint32(authMsg[16:], 0)                       // Flags
		authMsg[20] = 0                                                      // Section type
		authMsg = append(authMsg, authBSON...)

		fmt.Println("Authenticating")
		_, err = serverCon.Write(authMsg)
		if err != nil {
			fmt.Println("Error writing auth", err)
			return
		}
		lenbytes := make([]byte, 4)
		serverCon.Read(lenbytes)
		length := binary.LittleEndian.Uint32(lenbytes)
		databytes := make([]byte, length-4)
		serverCon.Read(databytes)

		go io.Copy(serverCon, con)
		io.Copy(con, serverCon)
		fmt.Println("Connection to", host, "closed")
	}

}

func (m *Manager) handleMongoConnections(listener net.Listener) {
	for {
		if con, err := listener.Accept(); err == nil {
			tlscon := tls.Server(con, m.config)
			if tlscon.Handshake() == nil {
				fmt.Println("Accepted connection to", tlscon.ConnectionState().ServerName)
				go handleMongoClient(m, tlscon, tlscon.ConnectionState().ServerName)
			}
		}
	}
}

func main() {
	var caCertPath string
	var serverPublicKeyPath string
	var serverPrivateKeyPath string
	var mongoHost string
	var tenantCertFolder string

	flag.StringVar(&caCertPath, "ca-cert-path", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "Path to the root CA certificate")
	flag.StringVar(&serverPublicKeyPath, "public-key-path", "server.cert.pem", "Path to the proxy servers public certificate")
	flag.StringVar(&serverPrivateKeyPath, "private-key-path", "server.key.pem", "Path to the proxy servers private key")
	flag.StringVar(&mongoHost, "mongo-host", "", "The address of the mongo cluster")
	flag.StringVar(&tenantCertFolder, "tenant-cert-folder", "", "The folder containing the tenant certificates")
	flag.Parse()

	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Fatal("Failed to root CA certificate", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Error appending root CA certificate to certificate pool")
	}
	serverCertificate, err := tls.LoadX509KeyPair(serverPublicKeyPath, serverPrivateKeyPath)
	if err != nil {
		log.Fatal("Failed to load server certificate", err)
	}
	tlsServerConfig := tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		RootCAs:      caPool,
	}
	manager := &Manager{
		validKeys:        make(map[string]string),
		config:           &tlsServerConfig,
		caPool:           caPool,
		mongoHost:        mongoHost,
		tenantCertFolder: tenantCertFolder,
	}

	fmt.Println("Starting MongoDB proxy")
	listener, err := net.Listen("tcp", "0.0.0.0:27017")
	if err != nil {
		log.Fatal(err)
	}
	go manager.handleMongoConnections(listener)

	fmt.Println("Starting RPC server")
	rpc.Register(manager)
	rpc.HandleHTTP()
	err = http.ListenAndServe("0.0.0.0:5557", nil)
	log.Fatal(err)
}
