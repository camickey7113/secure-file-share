import java.net.Socket;             // Used to connect to the server
import java.io.ObjectInputStream;   // Used to read objects sent from the server
import java.io.ObjectOutputStream;  // Used to write objects to the server
import java.io.BufferedReader;      // Needed to read from the console
import java.io.InputStreamReader;   // Needed to read from the console
import java.io.ObjectInput;
import java.util.*;

public class Client
{
    // Set up I/O streams with the Auth server
	private static ObjectOutputStream authOutput;
	private static ObjectInputStream authInput;
    // Set up I/O streams with the Resource server
	private static ObjectOutputStream resourceOutput;
	private static ObjectInputStream resourceInput;
    // Port numbers for each server
    private static int ResourcePortNumber;
    private static int AuthPortNumber;
    // Sockets for AS and RS
    private static Socket authSock;
    private static Socket resourceSock;
    // names of IP addresses to connect to
    private static String AuthIP;
    private static String ResourceIP;
    // Current user
    private static User currentUser;

    public static Scanner scanner = new Scanner (System.in);
    
    
    public static boolean connectToAuthServer() {
        System.out.println("Enter authentication server name: ");
        AuthIP = scanner.next();
        System.out.println("Enter authentication server port: ");
        AuthPortNumber = scanner.nextInt();
        try {
            authSock = new Socket(AuthIP, AuthPortNumber);
        } catch (Exception e) {
            System.out.println("Port connection failed\nlog: " + AuthIP + " : " + AuthPortNumber);
        }
        
        System.out.println("Connected to " + AuthIP + " on port " + AuthPortNumber);
        
        try {
            // Set up I/O streams with the server
            authOutput = new ObjectOutputStream(authSock.getOutputStream());
            authInput = new ObjectInputStream(authSock.getInputStream());
        } catch (Exception e) {
            System.out.println("I/O failed");
            return false;
        
        }
        System.out.println("Successful connection to Authentication Server");
        return true;
    }

    public static boolean connectToResourceServer() {
        System.out.println("Enter resource IP address");
        ResourceIP = scanner.next();
        System.out.println("Enter resource server port: ");
        ResourcePortNumber = scanner.nextInt();
        try {
            resourceSock = new Socket(ResourceIP, ResourcePortNumber);
        } catch (Exception e) {
            System.out.println("Port connection failed\nlog: " + ResourceIP + " : " + ResourcePortNumber);
        }
        System.out.println("Connected to " + ResourceIP + " on port " + ResourcePortNumber);
        
        // Set up I/O streams with the server
        try {
            resourceOutput = new ObjectOutputStream(resourceSock.getOutputStream());
            resourceInput = new ObjectInputStream(resourceSock.getInputStream());
        } catch (Exception e) {
            System.out.println("I/O failed");
        }
        
        System.out.println("Successful connection to Resource Server");
        return true;
    }

    // returns a Token that corresponds to the current user
    public static Token verifyUser() {
        Token t = null;
        // construct list with user
        ArrayList<Object> list = new ArrayList<Object>();
        list.add(currentUser);
        // send user to AS for verification 
        // receive response
        try {
            authOutput.writeObject(new Message("verify", list));
            t = (Token) ((Message) authInput.readObject()).getStuff().get(0);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        
        // if response is null, user was deleted
        if (t == null) {
            System.out.println("User no longer exists!");
        }
        // return user token
        return t;
    }

    public boolean handleCommand(String command, Token token) {
        
        if(command.equals("exit")){
            //close connections
            System.exit(0);
            return false;
        }
        else if(token.getUser().equals("root")){
            return sendCommand(command, token, authOutput);
        } else {
            return sendCommand(command, token, resourceOutput);
        }
    }

    private boolean sendCommand(String command, Token token, ObjectOutputStream serverstream) {
        try{
            ArrayList<Object> wrap = new ArrayList<Object>();
            wrap.add(token);
            Message newcommand = new Message(command, wrap);
            serverstream.writeObject(newcommand);
            return true;
        } catch (Exception e){
            System.err.println("Failed to send command with exception: " + e.getMessage());
            return false;
        }
    }

    // Prompts the user for a username and password
    // Upon successful login, returns a User object
    public static User login() {
        User potentialUser = null;
        // loop until a User is returned
        do {
            // construct list with user
            ArrayList<Object> list = new ArrayList<Object>();
            list.add(readCredentials());
            // send user to AS for verification 
            // receive response
            try {
                authOutput.writeObject(new Message("verify", list));
                potentialUser = (User) ((Message) authInput.readObject()).getStuff().get(0);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        } while (potentialUser == null);
        return potentialUser;
    }

    public static void main(String[] args) {
        // connect to auth server
        // connect to user server
        if(connectToAuthServer() && connectToResourceServer()) {
            System.out.println("Success!");
        }
        else {
            System.out.println("Error connecting to servers");
        }

        // login user
        try {
            currentUser = login();
        } catch (Exception e) {
            System.out.println("login unsuccessful");
        }

        System.out.println(currentUser.getUsername());
        
        // loop to accept commands
        Message msg;
        try {
            Scanner sc = new Scanner (System.in);
            do {
                // authenticate user
                Token t = verifyUser();
                if (t == null) {
                    System.out.println("Permission has been revoked. Please contact admin.");
                }
                // input command
                String inputs = sc.nextLine();
                // break if logout
                // send command
                // receive response
                // output response

                // Read and send message.  Since the Message class
                // implements the Serializable interface, the
                // ObjectOutputStream "output" object automatically
                // encodes the Message object into a format that can
                // be transmitted over the socket to the server.
                msg = new Message("message to resource server", readSomeText());
                resourceOutput.writeObject(msg);

                // Get ACK and print.  Since Message implements
                // Serializable, the ObjectInputStream can
                // automatically read this object off of the wire and
                // encode it as a Message.  Note that we need to
                // explicitly cast the return from readObject() to the
                // type Message.
                Message resp = (Message)(resourceInput).readObject();
                System.out.println("\nServer says: " + resp.getCommand() + "\n" + resp.getStuff().get(0));
            } while(!msg.getCommand().toUpperCase().equals("LOGOUT"));

        } catch (Exception e) {
            System.out.println("invalid resource command");
        }
        
        // logout
            // shut things down
            //authSock.close();
    }
    
     //-- end main(String[]) -----------------------------------------------------

    /**
     * Simple method to print a prompt and read a line of text.
     *
     * @return A line of text read from the console
     */
    private static ArrayList<Object> readSomeText()
    {
        try{
            //System.out.println("Enter a line of text, or type \"EXIT\" to quit.");
            System.out.print(" > ");	
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            String test = in.readLine();
            ArrayList<Object> list = new ArrayList<Object>();
            list.add(test);
            return list;
        }
        catch(Exception e){
            // Uh oh...
            return null;
        }

    } //-- end readSomeText()

    // returns a User object constructed from the username and password inputted
    private static User readCredentials()
    {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Username: ");
            String username = in.readLine();
            System.out.print("Password: ");
            String password = in.readLine();
            
            return new User(username, password, null);
        }
        catch(Exception e){
            // Uh oh...
            return null;
        }
    }
}