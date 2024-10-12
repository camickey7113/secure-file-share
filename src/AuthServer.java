import java.net.ServerSocket; // The server uses this to bind to a port
import java.net.Socket; // Incoming connections are represented as sockets
import java.util.*;
import java.io.File;

public class AuthServer {
    // port the server will use to connect
    public static final int SERVER_PORT = 8765;
    // list of all users in the system
    ArrayList<User> userList;

    private static AuthServer server;

    public AuthServer() {
        this.userList = new ArrayList<User>();
    }
    
    public boolean loadUserList(File userFile) {
        return false;
    }

    public boolean saveUserList(File userFile) {
        return false;
    }

    public void listenOnPort(int port) {

    }

    public void acceptIncomingConnection() {

    }

    public void start() {
        try {
            // This is basically just listens for new client connections
            final ServerSocket serverSock = new ServerSocket(SERVER_PORT);

            // A simple infinite loop to accept connections
            Socket sock = null;
            AuthThread thread = null;

            // create root and test users
            while (true) {
                sock = serverSock.accept(); // Accept an incoming connection
                thread = new AuthThread(this, sock); // Create a thread to handle this connection
                thread.start(); // Fork the thread
            } // Loop to work on new connections while this
                // the accept()ed connection is handled

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    public static void main(String[] args) {
        server = new AuthServer();
        server.start();
    }
}