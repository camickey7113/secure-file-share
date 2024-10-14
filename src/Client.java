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
        // Error checking for arguments
        if(args.length != 1)
            {
            System.err.println("Not enough arguments.\n");
            System.err.println("Usage:  java EchoClient <Server name or IP>\n");
            System.exit(-1);
            }

        try {
            // Connect to the specified server
            final Socket sock = new Socket(args[0], AuthServer.SERVER_PORT);
            System.out.println("Connected to " + args[0] + " on port " + AuthServer.SERVER_PORT);
            
            // Set up I/O streams with the server
            final ObjectOutputStream output = new ObjectOutputStream(sock.getOutputStream());
            final ObjectInputStream input = new ObjectInputStream(sock.getInputStream());

            // loop to send messages
            Message msg = null, resp = null, token = null;
            do {
                while(true){
                    // Read and send message.  Since the Message class
                    // implements the Serializable interface, the
                    // ObjectOutputStream "output" object automatically
                    // encodes the Message object into a format that can
                    // be transmitted over the socket to the server.
                    User possible = readCredentials();
                    output.writeObject(possible);

                    // Get ACK and print.  Since Message implements
                    // Serializable, the ObjectInputStream can
                    // automatically read this object off of the wire and
                    // encode it as a Message.  Note that we need to
                    // explicitly cast the return from readObject() to the
                    // type Message.
                    token = (Message)input.readObject();
                    System.out.println("\nServer says: " + token.getCommand() + "\n" + token.getStuff().get(0));
                    if(token != null) break;
                }

                do {
                    // Read and send message.  Since the Message class
                    // implements the Serializable interface, the
                    // ObjectOutputStream "output" object automatically
                    // encodes the Message object into a format that can
                    // be transmitted over the socket to the server.
                    msg = new Message(readSomeText(), null);
                    output.writeObject(msg);

                    // Get ACK and print.  Since Message implements
                    // Serializable, the ObjectInputStream can
                    // automatically read this object off of the wire and
                    // encode it as a Message.  Note that we need to
                    // explicitly cast the return from readObject() to the
                    // type Message.
                    resp = (Message)input.readObject();
                } while(!msg.getCommand().toUpperCase().equals("LOGOUT"));

            } while(!msg.getCommand().toUpperCase().equals("EXIT"));
            
            // shut things down
            sock.close();
        }

        catch(Exception e){
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

    } //-- end main(String[]) -----------------------------------------------------

    /**
     * Simple method to print a prompt and read a line of text.
     *
     * @return A line of text read from the console
     */
	private static String readSomeText() {
		try {
			// System.out.println("Enter a line of text, or type \"EXIT\" to quit.");
			System.out.print(" > ");
			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			return in.readLine();
		} catch (Exception e) {
			// Uh oh...
			return "";
		}

	} // -- end readSomeText()

	private static User readCredentials() {
		try {
			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			System.out.println("Username: ");
			String username = in.readLine();
			System.out.println("Password: ");
			String password = in.readLine();
			System.out.println();
			return new User(username, password, "group1");
		} catch (Exception e) {
			// Uh oh...
			System.err.println("error reading in username or password");
			System.exit(1);
			return null;
		}
	}

        
}