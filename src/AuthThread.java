import java.lang.Thread;
import java.net.Socket;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.*;

public class AuthThread extends Thread {
    private AuthServer server;
    private final Socket socket;

    public AuthThread(AuthServer server, Socket socket) {
        this.server = server;
        this.socket = socket;
    }

    public Token generateToken(User user) {
        Token newToken = new Token(user.getUsername(), user.getGroup());
        return newToken;

    }

    public boolean handleCommand(Message msg, ObjectOutputStream output) {
        ArrayList<Object> stuff = new ArrayList<Object>();
        Token t = msg.getToken();
        User user;
       

        try {
            switch (msg.getCommand()) {
                case "login":
                    user = (User) msg.getStuff().get(0); // <--- THIS IS WHATS FAILING
                    // authenticate the user
                    if (authenticate(user)) {
                        User authUser = server.getUserList().getUser(user.getUsername());
                        // get user from the username in the token
                        t = generateToken(authUser);
                        stuff.add(user);
                        // send message with token back to client:
                        output.writeObject(new Message(msg.getCommand(), t, stuff));
                    } else {
                        output.writeObject(new Message(msg.getCommand(), null, null));
                    }
                    break;
                    
                case "verify":
                    user = (User) msg.getStuff().get(0); // <--- THIS IS WHATS FAILING
                    // authenticate the user
                    if (authenticate(user)) {
                        User authUser = server.getUserList().getUser(user.getUsername());
                        // get user from the username in the token
                        t = generateToken(authUser);
                        stuff.add(user);
                        // send message with token back to client:
                        output.writeObject(new Message(msg.getCommand(), t, stuff));
                    } else {
                        output.writeObject(new Message(msg.getCommand(), null, null));
                    }
                    break;

                case "list":
                    //getting the desired group from the message
                    String listgroup = (String) msg.getStuff().get(0);
                    //retrieving the members
                    ArrayList<String> members = new ArrayList<String>();

                    Group g = server.getGroupList().getGroup(listgroup);
                    if(g == null){
                        stuff.add(false);
                        stuff.add("not a valid group");
                        output.writeObject(new Message(msg.getCommand(), null, stuff));
                        break;
                    }

                    stuff.add(true);
                    HashMap<String, User> m = g.getMembers().getUserMap();
                    //populate arraylist with usernames
                    for(String key: m.keySet()){
                        members.add(key);
                    }
                    stuff.add(members);
                    output.writeObject(new Message(msg.getCommand(), null, stuff));

                    break;

                case "create":
                    User newUser = (User) msg.getStuff().get(0);
                    if(server.getUserList().addUser(newUser)){
                        System.out.println("User " + newUser.getUsername() + " added.");
                        stuff.add(true);
                    } else {
                        stuff.add(false);
                    }
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "delete":
                    String oldUsername = (String) msg.getStuff().get(0);
                    if (server.getUserList().deleteUser(oldUsername)){
                        System.out.println("User " + oldUsername + " deleted.");
                        stuff.add(true);
                    } else {
                        stuff.add(false);
                    }
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "collect":
                    if(server.getGroupList().getGroup((String)msg.getStuff().get(0)) != null) {
                       stuff.add(false);
                    } else {
                        server.getGroupList().addGroup(new Group((String)(msg.getStuff()).get(0)));
                        stuff.add(true);
                    }
                        output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "release":
                    if(server.getGroupList().getGroup((String)msg.getStuff().get(0)) == null) {
                        stuff.add(false);
                    } else {
                        server.getGroupList().removeGroup((String)(msg.getStuff()).get(0));
                        stuff.add(true);
                    }
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;
                
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        
        return true;
    }

    // This function accepts a potential user object to be confirmed to exist in the
    // AS. If the user is found and the provided password matches return true.
    // Otherwise, return falsse.
    public boolean authenticate(User user) {
        if (server.getUserList().containsUser(user.getUsername()) && server.getUserList().getUser(user.getUsername()).getPassword().equals(user.getPassword())) {
            System.out.println("Username and Password accepted.");
            // if(!GroupList.containsGroup(user.getGroup())) {
            //     System.out.println("We messed up");
            //     return false;
            // }
            return true;
        } else {
            System.out.println("User and/or Group does not exist");
            return false;
        }
    }

    public void run() {
        try {
            // Print incoming message
            System.out.println("** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " **");

            // set up I/O streams with the client
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

            // Loop to read messages
            User authUser = null;

            Message msg = null;
            do {
                // read and print message
                msg = (Message) input.readObject();
                System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.getCommand());
                
                handleCommand(msg, output);


            } while (!msg.getCommand().toUpperCase().equals("EXIT"));

            File usersFile = new File("users.txt");
            File groupsFile = new File("groups.txt");

            if (server.saveUserList(usersFile)) {
                System.out.println("User list saved successfully");
            } else {
                System.err.println("Failed to save user list");
            }
    
            if (server.saveGroupList(groupsFile)) {
                System.out.println("Group list saved successfully");
            } else {
                System.err.println("Failed to save group list");
            }

            // Close and cleanup
            System.out
                    .println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
            socket.close();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}