import java.net.ServerSocket; // The server uses this to bind to a port
import java.net.Socket; // Incoming connections are represented as sockets
import java.util.*;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class AuthServer {
    // port the server will use to connect
    public static final int SERVER_PORT = 8765;
    // list of all users in the system
    private static UserList userList;
    private static GroupList groups;
    Group newGroup;

    private static AuthServer server;

    public AuthServer() {
        userList = new UserList();
        groups = new GroupList();
    }

    public UserList getUserList() {
        return userList;
    }
    public GroupList getGroupList() {
        return groups;
    }
    
    public static boolean loadUserAndGroupList(File userFile) {
        try {
            Scanner reader = new Scanner(new FileReader("users.txt"));
           
            while(reader.hasNextLine()){
                String userLine = reader.nextLine();
                String users[] = userLine.split(",");
                String username = users[0];
                String password = users[1];
                String group = users[2];
                User user = new User(username, password, group);
                // if the group does not exist, create it and add to global group list
                if(!groups.containsGroup(group)){
                    System.out.println("check");
                    Group newGroup = new Group(group);
                    groups.addGroup(newGroup);
                }
                // add the user to their group
                groups.getGroup(group).addMember(user);
                // add the user to the global user list
                userList.addUser(user);
               
     
            }
            reader.close();
            return true;
        }
        catch(IOException e){
            e.printStackTrace();
            
        }
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
        File usersFile = new File("users.txt");
        try{
           loadUserAndGroupList(usersFile);
        }
        catch(Exception e){
            System.out.println("Error Loading Users");
        }
        server.start();
    }
}