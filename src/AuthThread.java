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

    public boolean handleRootCommand(String command, Token token) {
        return false;
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
        for(String s : server.getUserList().userMap.keySet()) {
            System.out.println(s);
        }
        try {
            // Print incoming message
            System.out.println("** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " **");

            // set up I/O streams with the client
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

            Token token = null;
            while (token == null) {
                User authAttempt = (User)input.readObject();
                String username = authAttempt.getUsername();
                String password = authAttempt.getPassword();
                System.out.println("Received username: " + username);
                System.out.println("Received password: " + password);

                ArrayList<Object> theToken = new ArrayList<Object>();


             

                
                // got the user and pass. call authenticate on it.
                if (authenticate(username, password)) { // if we were able to authenticate, give them a token
                    token = generateToken(username);
                    theToken.add(token);
                    output.writeObject(new Message("Authentication successful", theToken)); // send token back to client
                } else {
                    output.writeObject(new Message("Authentication failed, try again", null)); // Failed authentication
                                                                                         // response
                }

            }

            // Loop to read messages
            User authUser = null;

            Message msg = null;
            do {
                // read and print message
                msg = (Message) input.readObject();
                System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.getCommand());
                // read and print message
                msg = (Message) input.readObject();
                System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.getCommand());

                // find out who is the current user
                if (msg.getCommand().equals("login")) {
                    User user = (User) msg.getStuff().get(0); // <--- THIS IS WHATS FAILING
                    // authenticate the user
                    if (authenticate(user)) {
                        System.out.println("check in run");
                        authUser = server.getUserList().getUser(user.getUsername());
                        // get user from the username in the msg
                        Token t = generateToken(authUser);
                        ArrayList<Object> stuff = new ArrayList<Object>();
                        stuff.add(user);
                        // send message with token back to client:
                        output.writeObject(new Message(msg.getCommand(), t, stuff));
                        // WRITE THIS ^
                    } else {
                        output.writeObject(new Message(msg.getCommand(), null, null));
                    }
                }

            } while (!msg.getCommand().toUpperCase().equals("EXIT"));

            // Close and cleanup
            System.out
                    .println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
            System.out
                    .println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
            socket.close();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

}