import java.net.Socket; // Used to connect to the server
import java.io.ObjectInputStream; // Used to read objects sent from the server
import java.io.ObjectOutputStream; // Used to write objects to the server
import java.io.BufferedReader; // Needed to read from the console
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader; // Needed to read from the console
import java.io.ObjectInput;
import java.util.*;

public class Client {
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

    public static Scanner scanner = new Scanner(System.in);

    public static boolean connectToAuthServer() {
        System.out.print("Enter authentication server name: ");
        // AuthIP = scanner.next();
        AuthIP = "localhost";
        System.out.print("Enter authentication server port: ");
        // AuthPortNumber = scanner.nextInt();
        AuthPortNumber = 8765;
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
        System.out.print("Enter resource server name: ");
        // ResourceIP = scanner.next();
        ResourceIP = "localhost";
        System.out.print("Enter resource server port: ");
        // ResourcePortNumber = scanner.nextInt();
        ResourcePortNumber = 8766;
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
            authOutput.writeObject(new Message("verify", null, list));
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

    // This method contains the logic for handling any commands made by the User,
    // root or not. A single string is given as input, which is broken up and
    // handled accordingly by an if-else statement.
    // return codes:
    //      0 : invalid command
    //      1 : empty/logout command
    //      2 : valid command
    public static int handleCommand(String line, Token token) {
        // break up command string by spaces
        String[] split = line.split("\\s+");
        ArrayList<Object> stuff = new ArrayList<Object>();
        Token t = new Token("testGroup1", "root");
        // empty input?
        if(line.isEmpty()) return 1;
        // exit?
        if (split[0].equals("exit")) {
            exit();
            System.out.print("Failed to exit...");
            return 1;
        }
        // logout?
        if (split[0].equals("logout")) {
            logout();
            return 1;
        }
            
        // determine if user is root and switch accordingly
        try {
            if (currentUser.getUsername() == "root") {
                switch (split[0].toLowerCase()) {
                    case "create":
                        // TODO root command
                        break;
                    case "delete":
                        // TODO root command
                        break;
                    case "collect":
                        if(split[1].isEmpty()) return 0;
                        stuff.add(split[1]);
                        resourceOutput.writeObject(new Message("collect", null, stuff));
                        break;
                    case "release":
                        if(split[1].isEmpty()) return 0;
                        stuff.add(split[1]);
                        resourceOutput.writeObject(new Message("release", null, stuff));
                        break;
                    case "assign":
                        // TODO root command
                        break;
                    case "list":
                        // TODO root command
                        break;
                    case "groups":
                        // TODO root command
                        break;
                    default:
                        return 0;
                }
            } else {
                switch (split[0]) {
                    case "list":
                        resourceOutput.writeObject(new Message("list", t, null));
                        break;
                    case "upload":
                        if(split[1].isEmpty()) return 0;
                        stuff.add(split[1]);
                        File file = new File(split[1]);
                        // Create a byte array with the size of the file
                        byte[] fileData = new byte[(int) file.length()];
                        // Use FileInputStream to read the file into the byte array
                        try (FileInputStream fileInputStream = new FileInputStream(file)) {
                            int bytesRead = fileInputStream.read(fileData);
                            if (bytesRead != fileData.length) {
                                throw new IOException("Could not read the entire file into the byte array.");
                            }
                        }
                        stuff.add(fileData);
                        resourceOutput.writeObject(new Message("upload", t, stuff));
                        break;
                    case "download":
                        if(split[1].isEmpty()) return 0;
                        stuff.add(split[1]);
                        resourceOutput.writeObject(new Message("download", t, stuff));
                        break;
                    default:
                        return 0;
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage() + " (in handleCommand)");
            return 1;
        }
        return 2;
    }

    public static boolean handleResponse() {
        try {
            //Message authResp = (Message) (authInput).readObject();
            Message resResp;
            if (currentUser.getUsername() == "root") {
                switch ("collect") {//dont forget
                    case "create":
                        // TODO root command
                        break;
                    case "delete":
                        // TODO root command
                        break;
                    case "collect":
                        resResp = (Message) (resourceInput).readObject();
                        return true;//return (boolean)authResp.getStuff().get(0) && (boolean)resResp.getStuff().get(0);
                        // TODO root command
                    case "release":
                        resResp = (Message) (resourceInput).readObject();
                        return true;//return (boolean)authResp.getStuff().get(0) && (boolean)resResp.getStuff().get(0);
                        // TODO root command
                    case "assign":
                        // TODO root command
                        break;
                    case "list":
                        // TODO root command
                        break;
                    default:
                        return false;
                }
            } else {
                Message resp = (Message) (resourceInput).readObject();
                switch (resp.getCommand()) {
                    case "list":
                        System.out.println(resp.getStuff().get(0));
                        break;
                    case "upload":
                        if((boolean)resp.getStuff().get(0)) {
                            System.out.println("File created successfully.");
                        } else {
                            System.out.println("An error has occurred. File was not created.");
                        }
                        break;
                    case "download":
                        if((boolean)resp.getStuff().get(0)) {
                            File file = new File((String)resp.getStuff().get(1));
                            file.createNewFile();
                            FileOutputStream fout = new FileOutputStream(file);
                            fout.write((byte[])resp.getStuff().get(2));
                            System.out.println("Download successful.");
                        } else {
                            System.out.println("An error has occurred. File not downloaded.");
                        }
                        break;
                    default:
                        return false;
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage() + " (in handleResponse)");
            return false;
        }
        return true;
    }

    @Deprecated
    private static boolean sendCommand(String command, Token token, ObjectOutputStream serverstream) {
        try {
            ArrayList<Object> wrap = new ArrayList<Object>();
            wrap.add(token);
            Message newcommand = new Message(command, null, wrap);
            serverstream.writeObject(newcommand);
            return true;
        } catch (Exception e) {
            System.err.println("Failed to send command with exception: " + e.getMessage());
            return false;
        }
    }

    // Prompts the user for a username and password
    // Upon successful login, returns a User object that may or may not exist in the
    // AS user list
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
                authOutput.writeObject(new Message("verify", null, list));
                potentialUser = (User) ((Message) authInput.readObject()).getStuff().get(0);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        } while (potentialUser == null);
        return potentialUser;
    }

    public static void logout() {
        currentUser = null;
    }

    public static void exit() {
        // cleanup stuff
        // TODO
        System.exit(0);
    }

    public static void main(String[] args) {
        // connect to AS and RS
        if (connectToAuthServer() && connectToResourceServer()) {
            System.out.println("Success! Both servers have connected!\n");
        } else {
            System.out.println("Error connecting to servers");
        }
        while (true) {
            // login user
            while (currentUser == null) {
                try {
                    currentUser = login();
                } catch (Exception e) {
                    System.out.println("Login unsuccessful. PLease try again.");
                }
            }

            // loop to accept commands
            Message msg;
            try {
                while (currentUser != null) {
                    // authenticate user
                    // Token t = verifyUser();
                    // if (t == null) {
                    // System.out.println("Permission has been revoked. Please contact admin.");
                    // }
                    // input command
                    System.out.println(currentUser.getUsername());
                    String inputs = readSomeText();
                    switch(handleCommand(inputs, null)) {
                        case 0:
                            throw new IllegalArgumentException("Invalid command.");
                        case 1:
                            continue;
                        case 2:
                            break;
                        default:
                            throw new Exception("Something is VERY wrong..."); 
                    }

                    handleResponse();
                        
                    // break if logout
                    // send command
                    // receive response
                    // output response

                    // Read and send message. Since the Message class
                    // implements the Serializable interface, the
                    // ObjectOutputStream "output" object automatically
                    // encodes the Message object into a format that can
                    // be transmitted over the socket to the server.
                    //---------------------------------------------------------------------------------------------------------------------------------
                    // msg = new Message("message", null);
                    // resourceOutput.writeObject(msg);
                    //---------------------------------------------------------------------------------------------------------------------------------


                    // Get ACK and print. Since Message implements
                    // Serializable, the ObjectInputStream can
                    // automatically read this object off of the wire and
                    // encode it as a Message. Note that we need to
                    // explicitly cast the return from readObject() to the
                    // type Message.
                    //---------------------------------------------------------------------------------------------------------------------------------
                    //Message resp = (Message) (resourceInput).readObject();
                    //---------------------------------------------------------------------------------------------------------------------------------
                    // System.out.println("\nServer says: " + resp.getCommand() + "\n" +
                    // resp.getStuff().get(0));
                }

            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }

        // logout
        // shut things down
        // authSock.close();
    }

    // -- end main(String[]) -----------------------------------------------------

    /**
     * Simple method to print a prompt and read a line of text.
     *
     * @return A line of text read from the console
     */
    private static String readSomeText() {
        try {
            System.out.print(" > ");
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            String input = in.readLine();
            return input;
        } catch (Exception e) {
            // Uh oh...
            return null;
        }

    } // -- end readSomeText()

    // returns a User object constructed from the username and password inputted
    private static User readCredentials() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Username: ");
            String username = in.readLine();
            System.out.print("Password: ");
            String password = in.readLine();

            return new User(username, password, null);
        } catch (Exception e) {
            // Uh oh...
            return null;
        }
    }
}