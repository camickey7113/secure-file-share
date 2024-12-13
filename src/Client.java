import java.net.Socket; // Used to connect to the server
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.io.ObjectInputStream; // Used to read objects sent from the server
import java.io.ObjectOutput;
import java.io.ObjectOutputStream; // Used to write objects to the server
import java.math.BigInteger;
import java.io.BufferedReader; // Needed to read from the console
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader; // Needed to read from the console
import java.io.ObjectInputStream; // Used to read objects sent from the server
import java.io.ObjectOutputStream; // Used to write objects to the server
import java.net.Socket; // Used to connect to the server
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

    //Auth and Resource Counters
    private static int authCounter;
    private static int resCounter;

    private static SecretKeySpec resHmacKey;
    private static SecretKeySpec authHmacKey;
    // public static final byte[] encodedDemoKey = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    private static PublicKey authPublicKey;
    private static PublicKey resPublicKey;

    public static Scanner scanner = new Scanner(System.in);

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static boolean connectToAuthServer() {
        System.out.print("Enter authentication server name: ");
        // AuthIP = scanner.next();
        AuthIP = "localhost";
        System.out.print("Enter authentication server port: ");
        // AuthPortNumber = scanner.nextInt();
        AuthPortNumber = 8000;
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

    public static User createUser(String username, String password, String group, String salt){
        
        User newUser = new User(username, password, group, salt);
        
        return newUser;
      

    }

    public static boolean connectToResourceServer() {
        System.out.print("Enter resource server name: ");
        // ResourceIP = scanner.next();
        ResourceIP = "localhost";
        System.out.print("Enter resource server port: ");
        // ResourcePortNumber = scanner.nextInt();
        ResourcePortNumber = 9000;
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

    public static User createUser(String username, String password, String group){
        User newUser = new User(username, password, group, null);
        return newUser;
    }

    // returns a Token that corresponds to the current user or null if the current
    // user was removed from the system after they already logged in
    @Deprecated
    public Token verifyUser() {
        byte[] encodedDemoKey = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        Token t = null;
        // construct list with user
        ArrayList<Object> list = new ArrayList<Object>();
        list.add(currentUser);
        SecretKeySpec AESkey = new SecretKeySpec(encodedDemoKey, "AES");
        try {
            // send user to AS for verification
            // byte[][] encryptedStuff = SymmetricEncrypt.symmEncrypt(AESkey,new Message("verify", null, list));
            // authOutput.writeObject(encryptedStuff);
            sendAuthMessage(new Message("verify", null, list), AESkey);
            // receive response

            Message response = SymmetricEncrypt.symmDecrypt(AESkey, (byte[][])authInput.readObject());
            t = response.getToken(); // stuck here
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
    public static int handleCommand(String line, Token token, byte[] signature, SecretKeySpec reskey, SecretKeySpec askey) {
        // break up command string by spaces
        String[] split = line.split("\s+");
        ArrayList<Object> stuff = new ArrayList<Object>();
        Token t = token;
        Message msg = null;

        // empty input?
        if (line.isEmpty())
            return 1;

        // exit?
        if (split[0].equals("exit")) {
            exit(askey, reskey);
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
            byte[][] encryptedStuff;
            if (currentUser.getUsername().equals("root")) {
                switch (split[0].toLowerCase()) {
                    case "create":
                        if (split[1].isEmpty() || split[2].isEmpty() || split[3].isEmpty()) return 0;
                        String username = split[1];
                        String password = split[2];
                        String group = split[3];

                        String salt = null; //ungenerated salt
                        stuff.add(createUser(username, password, group, salt));
                        
                        //we need two calls for two different keys
                        sendAuthMessage(new Message("create", t, stuff), askey);
                        sendResourceMessage(new Message("create", t, stuff), reskey);
                        // encryptedStuff = symmEncrypt(askey, new Message("create", null, stuff));
                        // authOutput.writeObject(encryptedStuff);
                        // encryptedStuff = symmEncrypt(reskey, new Message("create", null, stuff));
                        // resourceOutput.writeObject(encryptedStuff);

                        break;

                    case "delete":
                        if (split[1].isEmpty()) return 0;
                        String name = split[1];
                        stuff.add(name);
                        
                        //same as above, need two different calls bc normally two keys
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, new Message("delete", null, stuff));
                        // authOutput.writeObject(encryptedStuff);
                        sendAuthMessage(new Message("delete", t, stuff), askey);
                        // encryptedStuff = symmEncrypt(reskey, new Message("delete", null, stuff));
                        // resourceOutput.writeObject(encryptedStuff);
                        break;

                    case "collect":
                        if (split[1].isEmpty())
                            return 0;
                        stuff.add(split[1]);
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(reskey, new Message("collect", null, stuff));
                        // resourceOutput.writeObject(encryptedStuff);
                        sendResourceMessage(new Message("collect", t, stuff), reskey);
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, new Message("collect", null, stuff));
                        // authOutput.writeObject(encryptedStuff);
                        sendAuthMessage(new Message("collect", t, stuff), askey);
                        break;

                    case "release":
                        if (split[1].isEmpty())
                            return 0;
                        stuff.add(split[1]);
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, new Message("empty", null, stuff));
                        // authOutput.writeObject(encryptedStuff);
                        sendAuthMessage(new Message("empty", t, stuff), askey);

                        encryptedStuff = (byte[][]) authInput.readObject();
                        Message decrypted = SymmetricEncrypt.symmDecrypt(askey, encryptedStuff);

                        if ((boolean)decrypted.getStuff().get(0)) {
                            // encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, new Message("release", null, stuff));
                            // authOutput.writeObject(encryptedStuff);
                            sendAuthMessage(new Message("release", t, stuff), askey);
                            encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, new Message("release", t, stuff));
                            resourceOutput.writeObject(encryptedStuff);
                            sendResourceMessage(new Message("release", t, stuff), reskey);
                        } else {
                            System.out.println("Group not released - not empty or doesn't exist");
                            // encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, new Message("null", null, stuff));
                            // authOutput.writeObject(encryptedStuff);
                            sendAuthMessage(new Message("null", t, stuff), askey);
                            // encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, new Message("null", null, stuff));
                            // resourceOutput.writeObject(encryptedStuff);
                            sendResourceMessage(new Message("null", t, stuff), reskey);
                        }
                        break;

                    case "assign":
                        if (split[1].isEmpty() || split[2].isEmpty()) return 0;
                        stuff.add(split[1]);
                        stuff.add(split[2]);
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, new Message("assign", null, stuff));
                        // authOutput.writeObject(encryptedStuff);
                        sendAuthMessage(new Message("assign", t, stuff), askey);
                        break;

                    case "list":
                        if (split[1].isEmpty()) return 0;
                        stuff.add(split[1]);
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, new Message("list", null, stuff));
                        // authOutput.writeObject(encryptedStuff);
                        sendAuthMessage(new Message("list", t, stuff), askey);
                        break;

                    case "groups":
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, new Message("groups", null, null));
                        // authOutput.writeObject(encryptedStuff);
                        sendAuthMessage(new Message("groups", t, null), askey);
                        break;

                    default:
                        return 0;
                }
            } else {
                
                switch (split[0]) {
                    case "list":
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(reskey, new Message("list", t, signature, null));
                        // resourceOutput.writeObject(encryptedStuff);
                        sendResourceMessage(new Message("list", t, signature, null), reskey);
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
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(reskey, new Message("upload", t, signature, stuff));
                        // resourceOutput.writeObject(encryptedStuff);
                        sendResourceMessage(new Message("upload", t, signature, stuff), reskey);
                        break;

                    case "download":
                        if (split[1].isEmpty()) return 0;
                        stuff.add(split[1]);
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(reskey, new Message("download", t, signature, stuff));
                        // resourceOutput.writeObject(encryptedStuff);
                        sendResourceMessage(new Message("download", t, signature, stuff), reskey);
                        break;

                    default:
                        return 0;

                    case "delete":
                        if (split[1].isEmpty()) return 0;
                        stuff.add(split[1]);
                        // encryptedStuff = SymmetricEncrypt.symmEncrypt(reskey, new Message("delete", t, signature, stuff));
                        // resourceOutput.writeObject(encryptedStuff);
                        sendResourceMessage(new Message("delete", t, signature, stuff), reskey);
                        break;
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage() + " (in handleCommand)");
            return 1;
        }
        return 2;
    }

    
    public static boolean handleResponse(SecretKeySpec asKey, SecretKeySpec resKey) {
        try {
            Message authResp;
            Message resResp;
           
            if (currentUser.getUsername().equals("root")) {
                //authResp = SymmetricEncrypt.symmDecrypt(asKey, (byte[][])authInput.readObject());
                //intercept auth response before being decrypted 
                authResp = receiveAuthMessage(asKey, (byte[][])authInput.readObject());

                switch (authResp.getCommand()) {
                    case "create":
                        resourceInput.readObject();//useless but needs to be kept
                        if((boolean)authResp.getStuff().get(0)){
                            System.out.println("Created new user.");
                        } else {
                            System.out.println("Failed to create new user.");
                        }
                        return true;

                    case "delete":
                        if((boolean)authResp.getStuff().get(0)){
                            System.out.println("Deleted user.");
                        } else {
                            System.out.println("Failed to delete user.");
                        }
                        return true;

                    case "collect":
                        resResp = SymmetricEncrypt.symmDecrypt(resKey, (byte[][])resourceInput.readObject());
                        if((boolean)authResp.getStuff().get(0)){
                            System.out.println("Succesfully collected group.");
                        } else {
                            System.out.println("Failed to collect group.");
                        }
                        return true;

                    case "release":
                        resResp = SymmetricEncrypt.symmDecrypt(resKey, (byte[][])resourceInput.readObject());
                        if((boolean)authResp.getStuff().get(0)){
                            System.out.println("Succesfully released group.");
                        } else {
                            System.out.println("Failed to release group, not empty or doesn't exist.");
                        }
                        return true;
                    case "assign":
                        if((boolean)authResp.getStuff().get(0)){
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
                            for(int i = 0; i < members.size(); i++){
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
                        return (boolean)authResp.getStuff().get(0);

                    default:
                        return false;
                }
            } else {
                byte[][] nonsense = (byte[][])resourceInput.readObject();
                Message resp = receiveResourceMessage(resKey, nonsense);
                System.out.println(resp.getCommand());

                switch (resp.getCommand()) {
                    case "logout":
                        System.out.println("Token expired, please log back in...");
                        logout();
                        break;
                        
                    case "list":
                        ArrayList<Object> files = resp.getStuff();
                        for (int i = 0; i < files.size(); i++) {
                            System.out.println(files.get(i));
                        }
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
                        if((boolean) resp.getStuff().get(0)) {
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
    public static Message login(SecretKeySpec AESkey) {
        // construct list with user
        ArrayList<Object> list = new ArrayList<Object>();
        list.add(readCredentials());
        // add hashed public key to list
        list.add(resPublicKey);
        // send user to AS for verification
        try {
            // byte[][] encryptedStuff = SymmetricEncrypt.symmEncrypt(AESkey, new Message("login", null, list));
            // authOutput.writeObject(encryptedStuff);
            sendAuthMessage(new Message("login", null, list), AESkey);
            // receive response
            Message resp = receiveAuthMessage(AESkey, (byte[][]) authInput.readObject());
            System.out.println("got a response...");
            if(resp.getToken() == null) {
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

    public static void exit(SecretKeySpec asKey, SecretKeySpec resKey) {
        // cleanup stuff
        try {
            // byte[][] encryptedStuff = SymmetricEncrypt.symmEncrypt(asKey,new Message("exit", null, null));
            // authOutput.writeObject(encryptedStuff);
            sendAuthMessage(new Message("exit", null, null), asKey);
            // encryptedStuff = SymmetricEncrypt.symmEncrypt(resKey,new Message("exit", null, null));
            // resourceOutput.writeObject(encryptedStuff);
            sendResourceMessage(new Message("exit", null, null), resKey);
            authSock.close();
            resourceSock.close();
            currentUser = null;

            
        } catch (Exception e) {
            System.out.println("One or more servers were unable able to shut down, please try again.");
            return;
        }

        System.exit(0);
    }

    static boolean verifySig (byte[] signature, byte[] signed, PublicKey pubkey){
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA/PSS", BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(pubkey); // replace with AS public key
            verifier.update(signed);
            return verifier.verify(signature);
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
            return false;
        }
    }

    public static void sendAuthMessage(Message m, SecretKey askey) {
        // set counter
        m.setCounter(++authCounter);
        // System.out.println("Sent AS Counter: " + authCounter);
        // set hmac
        m.setHMAC(authHmacKey);
        // encrypt message
        byte[][] encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, m);
        // send message
        try {
            authOutput.writeObject(encryptedStuff);
        } catch (Exception e) {
            System.out.println("Error sending message: " + e.getMessage());
        }
    }

    public static void sendResourceMessage(Message m, SecretKey reskey) {
        // set counter
        m.setCounter(++resCounter);
        // set hmac
        m.setHMAC(resHmacKey);
        // encrypt message
        byte[][]encryptedStuff = SymmetricEncrypt.symmEncrypt(reskey, m);
        // send message
        try {
            resourceOutput.writeObject(encryptedStuff);
        } catch (Exception e) {
            System.out.println("Error sending message: " + e.getMessage());
        }
    }

    public static Message receiveAuthMessage(SecretKeySpec asKey, byte[][] encryptedMessage) {
        // decrypt
        Message m = SymmetricEncrypt.symmDecrypt(asKey, encryptedMessage);
        // check counter
        // System.out.println("Received AS Counter: " + authCounter);
        if(++authCounter != m.getCounter()) {
            System.out.println("Something's fishy...(counterAS)");
        }
        // check HMAC
        if (!m.checkHMAC(asKey)) {
            System.out.println("Something's fishy...(hmacAS)");
        }
        return m;
    }

    public static Message receiveResourceMessage(SecretKeySpec resKey, byte[][] encryptedMessage) {
         // decrypt
         Message m = SymmetricEncrypt.symmDecrypt(resKey, encryptedMessage);
         // check counter
         if(++resCounter != m.getCounter()) {
             System.out.println("Something's fishy...(counterRES)");
         }
         // check HMAC
         if (!m.checkHMAC(resKey)) {
             System.out.println("Something's fishy...(hmacRES)");
         }
         return m;
    }
    
    public static void main(String[] args) {

        authCounter = 0;
        resCounter = 0;
        
        // connect to AS and RS
        if (connectToAuthServer() && connectToResourceServer()) {
            System.out.println("Success! Both servers have connected!\n");
        } else {
            System.out.println("Error connecting to servers");
        }
        //load in auth and desired RS public keys from key files
        try {
            authPublicKey = KeyIO.readPublicKeyFromFile("authpublickey.txt");
            resPublicKey = KeyIO.readPublicKeyFromFile("respublickey.txt");
        } catch (IOException ex) {
            System.out.println("Failed to read in server public keys");
            System.out.println(ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
        
        //handshakes...
        SecretKeySpec authSessionKey = null;
        SecretKeySpec resSessionKey = null;
        try{
            ArrayList<SecretKeySpec> ret = Handshake.clientInitiateHandshake(authOutput, authInput, authPublicKey);
            authSessionKey = ret.get(0);
            authHmacKey = ret.get(1);
            ret = Handshake.clientInitiateHandshake(resourceOutput, resourceInput, resPublicKey);
            resSessionKey = ret.get(0);
            resHmacKey = ret.get(1);
            if (authSessionKey == null) {
                System.out.println("Failed to initiate auth handshake, exiting");
                System.exit(1);
            }
            if (resSessionKey == null) {
                System.out.println("Failed to initiate resource handshake, exiting");
                System.exit(1);
            }
        } catch (Exception e){
            System.out.println(e.getMessage());
            System.out.println("Exception in handshakes, exiting");
            System.exit(1);
        }
        // clientInitiateHandshake(authOutput, authInput);

        while (true) {
            // login user
            Message secret = null;
            Token t = null;
            byte[] s = null;
            while (currentUser == null) {
                try {
                    // System.out.println("Logging in...");
                    secret = login(authSessionKey);
                    // System.out.println("Logged in, retrieving token...");
                    t = secret.getToken();
                    // System.out.println("Obtained token, retrieving signature...");
                    s = secret.getSignature();
                    // System.out.println("Signature obtained...");
                } catch (Exception e) {
                    System.out.println("Login unsuccessful. Please try again.");
                }
            }            
            // loop to accept commands
            Message msg;
            try {
                while (currentUser != null) {
                    // input command
                    String inputs = readSomeText();
                    // System.out.println("Awaiting command...");
                    switch (handleCommand(inputs, t, s, resSessionKey, authSessionKey)) {
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
                    resourceOutput.flush();
                    authOutput.flush();
                    handleResponse(authSessionKey, resSessionKey);
                    resourceOutput.flush();
                    authOutput.flush();
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