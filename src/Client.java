import java.net.Socket;             // Used to connect to the server
import java.io.ObjectInputStream;   // Used to read objects sent from the server
import java.io.ObjectOutputStream;  // Used to write objects to the server
import java.io.BufferedReader;      // Needed to read from the console
import java.io.InputStreamReader;   // Needed to read from the console
import java.util.*;

public class Client
{
    // Set up I/O streams with the Auth server
	ObjectOutputStream authOutput;
	ObjectInputStream authInput;
    // Set up I/O streams with the Resource server
	ObjectOutputStream resourceOutput;
	ObjectInputStream resourceInput;
    // Port numbers for each server
    int ResourcePortNumber;
    int AuthPortNumber;

    public boolean connectToAuthServer(int port, String ip) {
        return false;
    }

    public boolean connectToResourceServer(int port, String ip) {
        return false;
    }

    public Token verifyUser(String User) {
        return null;
    }

    public boolean handleCommand(String command, Token token) {
        return false;
    }

    private boolean sendRootCommand(String command, Token token) {
        return false;
    }

    private boolean sendResourceCommand(String command, Token token) {
        return false;
    }

    public static void main(String[] args) {
        
	}

} //-- end class EchoClient