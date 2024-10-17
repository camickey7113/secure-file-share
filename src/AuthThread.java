import java.lang.Thread;
import java.net.Socket;
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
                    //Group newGroup = newUser.getGroup();
                    if(server.getUserList().addUser(newUser)){
                        System.out.println("User " + newUser.getUsername() + " added.");
                        server.saveUserList("users.txt");
                        //stuff.add(true); add in later

                        //if group assigning exists assign user to that group
                        //otherwise create a new group
                        if(server.getGroupList().containsGroup(newUser.getGroup())){
                            Group existingGroup = server.getGroupList().getGroup(newUser.getGroup());
                            existingGroup.addMember(newUser);
                            stuff.add(true);
                        }
                        else {
                            Group newGroup = new Group (newUser.getGroup());
                            server.getGroupList().addGroup(newGroup);
                            newGroup.addMember(newUser);
                            server.saveGroupList("groups.txt");
                            stuff.add(true);
                        }
                    } else {
                        stuff.add(false);
                    }
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

              case "delete":    
                    String deletedUsername = (String) msg.getStuff().get(0);
                
                    if(server.getUserList().containsUser(deletedUsername)){
                        User deletedUser = server.getUserList().getUser(deletedUsername);
                        Group existingGroup = server.getGroupList().getGroup(deletedUser.getGroup());
                        existingGroup.removeMember(deletedUser);
                        if (server.getUserList().deleteUser(deletedUser)){
                            System.out.println("User " + deletedUser.getUsername() + " deleted.");
                       
                            stuff.add(true);
                        }
                    }
                    else{
                        System.out.println("User doesn't exist!");
                        stuff.add(false);
                    }
                   
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "collect":
                    if(server.getGroupList().getGroup((String)msg.getStuff().get(0)) != null) {
                       stuff.add(false);
                    } else {
                        server.getGroupList().addGroup(new Group((String)(msg.getStuff()).get(0)));
                        server.saveGroupList("groups.txt");
                        stuff.add(true);
                    }
                        output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "empty":
                    Group e = server.getGroupList().getGroup((String)msg.getStuff().get(0));
                    if (e == null){
                        stuff.add(false);
                    } else if (e.getMembers().hasMembers()) {
                        stuff.add(false);
                    } else {
                        stuff.add(true);
                    }
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    stuff.remove(0);
                    break;

                case "release":
                    System.out.println("releasing...");
                    Group delGroup = server.getGroupList().getGroup((String)msg.getStuff().get(0));
                    //some redundant error checking
                    if(delGroup == null) { //if the group doesnt exist
                        stuff.add(false);
                    } if(delGroup.getMembers().size() != 0){ //if the group isnt empty
                        stuff.add(false);
                    } else {
                        server.getGroupList().removeGroup((String)(msg.getStuff()).get(0));
                        server.saveGroupList("groups.txt");
                        stuff.add(true);
                    }
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "assign":
                    // confirm that group and user exist
                    if (server.getGroupList().getGroup((String)msg.getStuff().get(1)) == null || server.getUserList().getUser((String)msg.getStuff().get(0)) == null) {
                        stuff.add(false);
                        System.out.println("Cannot assign, either user or group are not valid.");
                    } else {
                        // get user object
                        User assignee = server.getUserList().getUser((String)msg.getStuff().get(0));
                        // remove user from old group
                        server.getGroupList().getGroup(assignee.getGroup()).removeMember(assignee);
                        // change group field in user
                        assignee.setGroup((String)msg.getStuff().get(1));
                        // add user to new group
                        server.getGroupList().getGroup((String)msg.getStuff().get(1)).addMember(assignee);
                        server.saveUserList("users.txt");
                        // return success
                        stuff.add(true);

                    }
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    // change group in user object
                    break;

                case "groups":
                    // return list of groups
                    stuff.add(true);
                    stuff.add(server.getGroupList().getGroupNames());
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "null":
                    stuff.add(false);
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