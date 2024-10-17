import java.net.ServerSocket; // The server uses this to bind to a port
import java.net.Socket; // Incoming connections are represented as sockets
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
    //Group newGroup;

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
    
    public static boolean loadUserAndGroupList(File userFile, File groupFile) {
        try {
            Scanner reader = new Scanner(userFile);
           
            while(reader.hasNextLine()){
                String userLine = reader.nextLine();
                String users[] = userLine.split(",");
                String username = users[0];
                String password = users[1];
                String group = users[2].trim();
                User user = new User(username, password, group);
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
                w.append(user.getUsername()+","+user.getPassword()+","+user.getGroup()+ System.lineSeparator());
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

    public void listenOnPort(int port) {

    }

    public void acceptIncomingConnection() {

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
        server = new AuthServer();
        File usersFile = new File("users.txt");
        File groupFile = new File("groups.txt");
        try{
           loadUserAndGroupList(usersFile, groupFile);
        }
        catch(Exception e){
            System.out.println("Error Loading Users");
        }
        server.start();
    }
}