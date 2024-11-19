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
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

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
    private static User newUser;

    public static Scanner scanner = new Scanner(System.in);

    public static boolean connectToAuthServer() {
        System.out.print("Enter authentication server name: ");
        AuthIP = scanner.next();
        // AuthIP = "localhost";
        System.out.print("Enter authentication server port: ");
        AuthPortNumber = scanner.nextInt();
        // AuthPortNumber = 8765;
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

    public static User createUser(String username, String password, String group, String salt) {

        User newUser = new User(username, password, group, salt);

        return newUser;

    }


    // dh stuff 

    private static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(2048);
        // initilize diffie hellman size 2048
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        return keyGen.generateKeyPair();

    }

    private static SecretKey deriveAESKey(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] aesKeyBytes = sha256.digest(sharedSecret);
        return new SecretKeySpec(aesKeyBytes, 0, 16, "AES");
    }

    public static void performHandshake(ObjectOutputStream output, ObjectInputStream input) throws Exception {
        // generate DH key pair
        KeyPair clientDHKeys = generateDHKeyPair();
        PublicKey clientPublicKey = clientDHKeys.getPublic();

        // send client's public DH key to server
        output.writeObject(clientPublicKey);
        output.flush();

        // receive servers public key and signature
        PublicKey serverPublicKey = (PublicKey) input.readObject();
        byte[] serverSignature = (byte[]) input.readObject();

        // verify servers identity
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(serverPublicKey); // Replace with a pre-shared server public key
        verifier.update(serverPublicKey.getEncoded());
        if (!verifier.verify(serverSignature)) {
            throw new SecurityException("Server verification failed!");
        }

        // derive aes session key
        SecretKey aesKey = deriveAESKey(clientDHKeys.getPrivate(), serverPublicKey);

        // confirm session key
        byte[] confirmationMessage = (byte[]) input.readObject();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        String confirmation = new String(cipher.doFinal(confirmationMessage));
        if (!"SLAY".equals(confirmation)) {
            throw new SecurityException("Session key confirmation failed!");
        }

        // further communication can now use aesKey for encryption
    }


    ////// end dh stuff ///////////



    public static boolean connectToResourceServer() {
        System.out.print("Enter resource server name: ");
        ResourceIP = scanner.next();
        // ResourceIP = "localhost";
        System.out.print("Enter resource server port: ");
        ResourcePortNumber = scanner.nextInt();
        // ResourcePortNumber = 8766;
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
            return false;
        }

        System.out.println("Successful connection to Resource Server");
        return true;
    }

    public static User createUser(String username, String password, String group) {
        User newUser = new User(username, password, group, null);
        return newUser;
    }

    // returns a Token that corresponds to the current user or null if the current
    // user was removed from the system after they already logged in
    @Deprecated
    public static Token verifyUser() {
        Token t = null;
        // construct list with user
        ArrayList<Object> list = new ArrayList<Object>();
        list.add(currentUser);
        try {
            // send user to AS for verification
            authOutput.writeObject(new Message("verify", null, list));
            // receive response
            t = (Token) ((Message) authInput.readObject()).getToken(); // stuck here
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        // if response is null, user was deleted
        if (t == null) {
            System.out.println("User no longer exists!");
        }
        // return user token (or null)
        return t;
    }

    // This method contains the logic for handling any commands made by the User,
    // root or not. A single string is given as input, which is broken up and
    // handled accordingly by an if-else statement.
    // return codes:
    // 0 : invalid command
    // 1 : empty/logout command
    // 2 : valid command
    public static int handleCommand(String line, Token token, byte[] signature) {
        // break up command string by spaces
        String[] split = line.split("\\s+");
        ArrayList<Object> stuff = new ArrayList<Object>();
        Token t = token;
        Message msg = null;

        // empty input?
        if (line.isEmpty())
            return 1;

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
            if (currentUser.getUsername().equals("root")) {
                switch (split[0].toLowerCase()) {
                    case "create":
                        if (split[1].isEmpty() || split[2].isEmpty() || split[3].isEmpty())
                            return 0;
                        String username = split[1];
                        String password = split[2];
                        String group = split[3];
                        String salt = null; // ungenerated salt
                        stuff.add(createUser(username, password, group, salt));
                        authOutput.writeObject(new Message("create", null, stuff));
                        resourceOutput.writeObject(new Message("create", null, stuff));
                        break;

                    case "delete":
                        if (split[1].isEmpty())
                            return 0;
                        String name = split[1];
                        stuff.add(name);
                        authOutput.writeObject(new Message("delete", null, stuff));
                        resourceOutput.writeObject(new Message("delete", null, stuff));
                        break;

                    case "collect":
                        if (split[1].isEmpty())
                            return 0;
                        stuff.add(split[1]);
                        msg = new Message("collect", null, stuff);
                        resourceOutput.writeObject(msg);
                        authOutput.writeObject(msg);
                        break;

                    case "release":
                        if (split[1].isEmpty())
                            return 0;
                        stuff.add(split[1]);
                        authOutput.writeObject(new Message("empty", null, stuff));
                        if ((boolean) ((Message) authInput.readObject()).getStuff().get(0)) {
                            msg = new Message("release", null, stuff);
                            authOutput.writeObject(msg);
                            resourceOutput.writeObject(msg);
                        } else {
                            msg = new Message("null", null, stuff);
                            System.out.println("Group not released - not empty or doesn't exist");
                            authOutput.writeObject(msg);
                            resourceOutput.writeObject(msg);
                        }
                        break;

                    case "assign":
                        if (split[1].isEmpty() || split[2].isEmpty())
                            return 0;
                        stuff.add(split[1]);
                        stuff.add(split[2]);
                        authOutput.writeObject(new Message("assign", null, stuff));
                        break;

                    case "list":
                        if (split[1].isEmpty())
                            return 0;
                        stuff.add(split[1]);
                        authOutput.writeObject(new Message("list", null, stuff));
                        break;

                    case "groups":
                        authOutput.writeObject(new Message("groups", null, null));
                        break;

                    default:
                        return 0;
                }
            } else {
                switch (split[0]) {
                    case "list":
                        resourceOutput.writeObject(new Message("list", t, signature, null));
                        break;

                    case "upload":
                        if (split[1].isEmpty())
                            return 0;
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
                        resourceOutput.writeObject(new Message("upload", t, signature, stuff));
                        break;

                    case "download":
                        if (split[1].isEmpty())
                            return 0;
                        stuff.add(split[1]);
                        resourceOutput.writeObject(new Message("download", t, signature, stuff));
                        break;

                    default:
                        return 0;

                    case "delete":
                        if (split[1].isEmpty())
                            return 0;
                        stuff.add(split[1]);
                        resourceOutput.writeObject(new Message("delete", t, signature, stuff));
                        break;
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
            Message authResp;
            Message resResp;
            if (currentUser.getUsername().equals("root")) {
                authResp = (Message) authInput.readObject();
                switch (authResp.getCommand()) {
                    case "create":
                        if ((boolean) authResp.getStuff().get(0)) {
                            System.out.println("Created new user.");
                        } else {
                            System.out.println("Failed to create new user.");
                        }
                        return true;

                    case "delete":
                        if ((boolean) authResp.getStuff().get(0)) {
                            System.out.println("Deleted user.");
                        } else {
                            System.out.println("Failed to delete user.");
                        }
                        return true;

                    case "collect":
                        resResp = (Message) resourceInput.readObject();
                        if ((boolean) authResp.getStuff().get(0)) {
                            System.out.println("Succesfully collected group.");
                        } else {
                            System.out.println("Failed to collect group.");
                        }
                        return (boolean) authResp.getStuff().get(0) && (boolean) resResp.getStuff().get(0);

                    case "release":
                        resResp = (Message) resourceInput.readObject();
                        if ((boolean) authResp.getStuff().get(0)) {
                            System.out.println("Succesfully released group.");
                        } else {
                            System.out.println("Failed to release group, not empty or doesn't exist.");
                        }
                        return (boolean) authResp.getStuff().get(0) && (boolean) resResp.getStuff().get(0);

                    case "assign":
                        if ((boolean) authResp.getStuff().get(0)) {
                            System.out.println("Succesfully assigned user to group");
                            return true;
                        } else {
                            System.out.println("Failed to assign user to group -> either group or user" +
                                    " is invalid");
                            return false;
                        }

                    case "list":
                        if ((boolean) authResp.getStuff().get(0)) {
                            @SuppressWarnings("unchecked")
                            ArrayList<String> members = (ArrayList<String>) authResp.getStuff().get(1);
                            for (int i = 0; i < members.size(); i++) {
                                System.out.println(members.get(i));
                            }
                        } else {
                            System.out.println((String) authResp.getStuff().get(1));
                        }
                        break;

                    case "groups":
                        @SuppressWarnings("unchecked")
                        ArrayList<String> groups = (ArrayList<String>) authResp.getStuff().get(1);
                        for (String s : groups) {
                            System.out.println(s);
                        }
                        return (boolean) authResp.getStuff().get(0);

                    default:
                        return false;
                }
            } else {
                Message resp = (Message) resourceInput.readObject();
                // if signature is null, signature was rejected
                if (resp.getSignature() == null) {
                    System.out.println("Something's fishy...");
                    return false;
                }
                switch (resp.getCommand()) {
                    case "list":
                        System.out.println(resp.getStuff().get(0));
                        break;

                    case "upload":
                        if ((boolean) resp.getStuff().get(0)) {
                            System.out.println("File created successfully.");
                        } else {
                            System.out.println("An error has occurred. File was not created.");
                        }
                        break;

                    case "download":
                        if ((boolean) resp.getStuff().get(0)) {
                            File file = new File((String) resp.getStuff().get(1));
                            file.createNewFile();
                            FileOutputStream fout = new FileOutputStream(file);
                            fout.write((byte[]) resp.getStuff().get(2));
                            System.out.println("Download successful.");
                        } else {
                            System.out.println("An error has occurred. File not downloaded.");
                        }
                        break;

                    case "delete":
                        if ((boolean) resp.getStuff().get(0)) {
                            System.out.println("File deleted successfully.");
                        } else {
                            System.out.println("File was unable to be deleted.");
                        }

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
    // Upon successful login, returns a Message object containing a user's details
    public static Message login() {
        // construct list with user
        ArrayList<Object> list = new ArrayList<Object>();
        list.add(readCredentials());
        // System.out.println("made it here");
        // send user to AS for verification
        // receive response
        try {
            authOutput.writeObject(new Message("login", null, list));

            Message resp = (Message) authInput.readObject();
            if (resp.getToken() == null) {
                return null;
            }
            System.out.println("Token Generated");
            currentUser = (User) resp.getStuff().get(0);
            return resp;

            // ^wat dis doins
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static void logout() {
        currentUser = null;
    }

    public static void exit() {
        // cleanup stuff
        try {
            authOutput.writeObject(new Message("exit", null, null));
            resourceOutput.writeObject(new Message("exit", null, null));
            authSock.close();
            resourceSock.close();
            currentUser = null;

        } catch (Exception e) {
            System.out.println("One or more servers was able to shut down, please try again.");
            return;
        }

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
            Message secret = null;
            Token t = null;
            byte[] s = null;
            while (currentUser == null) {
                try {
                    secret = login();
                    t = secret.getToken();
                    s = secret.getSignature();
                } catch (Exception e) {
                    System.out.println("Login unsuccessful. Please try again.");
                }
            }

            // loop to accept commands
            Message msg;
            try {
                while (currentUser != null) {
                    // authenticate user
                    // if unable to verify, user will need to re-login
                    // if (t == null) {
                    // System.out.println("Permission has been revoked. Please contact admin.");
                    // logout();
                    // continue;
                    // } else {
                    // System.out.println("Successfully verified\nCurrent user: " +
                    // currentUser.getUsername());
                    // }

                    // input command
                    String inputs = readSomeText();
                    // System.out.println("Awaiting command...");
                    switch (handleCommand(inputs, t, s)) {
                        case 0:
                            throw new IllegalArgumentException("Invalid command.");
                        case 1:
                            continue;
                        case 2:
                            break;
                        default:
                            throw new Exception("Something is VERY wrong...");
                    }
                    // System.out.println("Received command...");
                    // System.out.println("Awaiting response...");
                    handleResponse();
                    // System.out.println("Received response...");
                }

            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
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

            return new User(username, password, null, null);
        } catch (Exception e) {
            // Uh oh...
            return null;
        }
    }

}