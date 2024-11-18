import java.net.ServerSocket; // The server uses this to bind to a port
import java.net.Socket; // Incoming connections are represented as sockets
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.io.File;

public class ResourceServer {
    // port the server will use to connect
    public static final int SERVER_PORT = 8766;
    // map of groups and files that each owns
    private static ResourceServer server;

    private static PublicKey rsPubKey;
    private static PrivateKey rsPrivKey;

    private static PublicKey authPublicKey;
    
    

    public void listenOnPort(int port) {

    }

    public void acceptIncomingConnection() {

    }

    public PublicKey getAuthKey() {
        return authPublicKey;
    }

    public void start() {
        try{
            // This is basically just listens for new client connections
            Scanner scanner = new Scanner(System.in);
            int ResourcePort;
            // This is basically just listens for new client connections
            System.out.print("Enter Resource Server port you want to connect to: ");
            ResourcePort = scanner.nextInt();
            final ServerSocket serverSock = new ServerSocket(ResourcePort);
            scanner.close();
           
            // obtain AS public key
            authPublicKey = KeyIO.readPublicKeyFromFile("authpublickey.txt");

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