import java.net.ServerSocket; // The server uses this to bind to a port
import java.net.Socket; // Incoming connections are represented as sockets
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.*;
import java.io.File;
import java.io.IOException;

public class ResourceServer {
    // port the server will use to connect
    public static final int SERVER_PORT = 8766;
    // map of groups and files that each owns
    private static ResourceServer server;

    private static PublicKey resPublicKey;
    private static PrivateKey resPrivateKey;

    private static PublicKey authPublicKey;

    public PublicKey getAuthKey() {
        return authPublicKey;
    }

    public PublicKey getPublicKey() {
        return resPublicKey;
    }

    public PrivateKey getPrivateKey() {
        return resPrivateKey;
    }

    public static KeyPair generateKeyPair() throws Exception {
        // Create key generator using RSA and BouncyCastle
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        // Initialize to create 4096-bit key pairs
        keyGen.initialize(4096, new SecureRandom());
        // Generate and return key
        return keyGen.generateKeyPair();
    }
    
    public static boolean loadServerKeys(String publicKeyFilename, String privateKeyFilename) {
        try {
            resPrivateKey = KeyIO.readPrivateKeyFromFile(privateKeyFilename);
            resPublicKey = KeyIO.readPublicKeyFromFile(publicKeyFilename);
            if(resPrivateKey == null || resPublicKey == null) return false;
            return true;
        } catch (Exception e) {
            System.out.println("error reading keys from files : " + e.getMessage());
            return false;
        }
    }

    public void start() {
        try{
            // obtain AS public key
            authPublicKey = KeyIO.readPublicKeyFromFile("respublickey.txt");

            // obtain RS keys
            if(!loadServerKeys("respublickey.txt", "resprivatekey.txt")) {
                try {
                    KeyPair authKeys = generateKeyPair();
                    resPublicKey = authKeys.getPublic();
                    resPrivateKey = authKeys.getPrivate();
                } catch (Exception a) {
                    a.printStackTrace();
                    System.out.println("We're cooked.");
                    System.exit(1);
                }
                //savetofile
                try {
                    KeyIO.writeKeyToFile("respublickey.txt", resPublicKey.getEncoded());
                    KeyIO.writeKeyToFile("resprivatekey.txt", resPrivateKey.getEncoded());
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }

            // This is basically just listens for new client connections
            Scanner scanner = new Scanner(System.in);
            int ResourcePort;
            // This is basically just listens for new client connections
            System.out.print("Enter Resource Server port you want to connect to: ");
            ResourcePort = scanner.nextInt();
            final ServerSocket serverSock = new ServerSocket(ResourcePort);
            scanner.close();

            // A simple infinite loop to accept connections
            Socket sock = null;
            ResourceThread thread = null;
            while(true){
                sock = serverSock.accept();     // Accept an incoming connection
                thread = new ResourceThread(this, sock);  // Create a thread to handle this connection
                thread.start();                 // Fork the thread
            }                                   // Loop to work on new connections while this
                                                // the accept()ed connection is handled
        }
        catch(Exception e){
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    public static void main(String[] args) {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        server = new ResourceServer();
        server.start();
    }
}