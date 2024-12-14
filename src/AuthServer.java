import java.net.ServerSocket; // The server uses this to bind to a port
import java.net.Socket; // Incoming connections are represented as sockets
import java.security.*;
import java.util.*;

import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class AuthServer {
    // port the server will use to connect
    public static final int SERVER_PORT = 8765;
    // list of all users in the system
    private static UserList userList;
    public static GroupList groups;
    private static HashMap<String, GroupKey> groupKeys;

    private static PublicKey authPublicKey;
    private static PrivateKey authPrivateKey;

    private static AuthServer server;

    public AuthServer() {
        userList = new UserList();
        groups = new GroupList();
        groupKeys = new HashMap<String, GroupKey>();
    }

    public HashMap<String, GroupKey> getGroupKeys() {
        return groupKeys;
    }

    public UserList getUserList() {
        return userList;
    }
    public GroupList getGroupList() {
        return groups;
    }

    public PublicKey getPublicKey() {
        return authPublicKey;
    }

    public PrivateKey getPrivateKey() {
        return authPrivateKey;
    }
    
    public static boolean loadUserAndGroupList(File userFile, File groupFile) {
        try {
            Scanner reader = new Scanner(userFile);
            while(reader.hasNextLine()){
                String userLine = reader.nextLine();
                String users[] = userLine.split(",");
                String username = users[0];
                String password = users[1];
                String group = users[2].trim();
                String salt = users[3];
                User user = new User(username, password, group, salt);
                // if the group does not exist, create it and add to global group list
                if(!groups.containsGroup(group)){
                    Group newGroup = new Group(group);
                    groups.addGroup(newGroup);
                }
                // add the user to their group
                groups.getGroup(group).addMember(user);
                // add the user to the global user list
                userList.addUser(user);
            }
            reader.close();
            //sanity check our groups list file
            reader = new Scanner(groupFile);
           
            while(reader.hasNextLine()){
                String group = reader.nextLine();
                group.trim();
                // if the group does not exist, create it and add to global group list
                if(!groups.containsGroup(group)){
                    Group newGroup = new Group(group);
                    groups.addGroup(newGroup);
                }
            }
            reader.close();
            return true;
        }
        catch(IOException e){
            e.printStackTrace();
            
        }
        return false;
    }

    public synchronized boolean saveUserList(String userFile) {
        try {
            FileWriter w = new FileWriter(userFile);
            w.write("");
            HashMap<String, User> u = userList.getUserMap();
            for(User user: u.values()){
                w.append(user.getUsername()+","+user.getPassword()+","+user.getGroup() + ","+ user.getSalt() + System.lineSeparator());
            }
            w.close();
            return true;
        } catch (Exception e) {
            System.err.println("Error saving userlist to file ->" + e.getMessage());
            return false;
        }
    }
    public synchronized boolean saveGroupList(String groupFile) {
        try {
            FileWriter w = new FileWriter(groupFile);
            w.write("");
            HashMap<String, Group> g = groups.getGroupMap();
            for(String groupname: g.keySet()){
                w.append(groupname + System.lineSeparator());
            }
            w.close();
            return true;
        } catch (Exception e) {
            System.err.println("Error saving userlist to file ->" + e.getMessage());
            return false;
        }
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
            authPrivateKey = KeyIO.readPrivateKeyFromFile(privateKeyFilename);
            authPublicKey = KeyIO.readPublicKeyFromFile(publicKeyFilename);
            if(authPrivateKey == null || authPublicKey == null) return false;
            return true;
        } catch (Exception e) {
            System.out.println("error reading keys from files : " + e.getMessage());
            return false;
        }
    }

    public void start() {
        try {
            Scanner scanner = new Scanner(System.in);
            int AuthPort;
            // This is basically just listens for new client connections
            System.out.print("Enter Auth Server port you want to connect to: ");
            AuthPort = scanner.nextInt();
            final ServerSocket serverSock = new ServerSocket(AuthPort);
            scanner.close();
            // A simple infinite loop to accept connections
            Socket sock = null;
            AuthThread thread = null;

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
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            if(!loadServerKeys("authpublickey.txt", "authprivatekey.txt")) {
                try {
                    KeyPair authKeys = generateKeyPair();
                    authPublicKey = authKeys.getPublic();
                    authPrivateKey = authKeys.getPrivate();
                } catch (Exception a) {
                    a.printStackTrace();
                    System.out.println("We're cooked.");
                    System.exit(1);
                }
                //savetofile
                
    
                try {
                    KeyIO.writeKeyToFile("authpublickey.txt", authPublicKey.getEncoded());
                    KeyIO.writeKeyToFile("authprivatekey.txt", authPrivateKey.getEncoded());
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }

        server = new AuthServer();
        File usersFile = new File("users.txt");
        File groupFile = new File("groups.txt");
        File groupKeyFile = new File("groupkeys.txt");
        try{
            loadUserAndGroupList(usersFile, groupFile);
            //loadGroupKeys(groupKeyFile);
        }
        catch(Exception e){
            System.out.println("Error Loading Users");
        }
        server.start();
    }
}