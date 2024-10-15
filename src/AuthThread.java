import java.lang.Thread;
import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.*;

public class AuthThread extends Thread {
    private AuthServer server;
    private final Socket socket;
    private final ArrayList<User> userList;

    public AuthThread(AuthServer server, Socket socket, ArrayList<User> userList) {
        this.server = server;
        this.socket = socket;
        this.userList = userList;
    }

	private Token generateToken(String username) {
		if (username.equals("root")) {
			return new Token(username, null); // root user, no group
		} else {
			String group = "group1"; // i just hard coded for now, will have to fix later
			return new Token(username, group); // student with group
		}
	}

	private boolean authenticate(String username, String password){
		for (User user: userList){
			if (user.getUsername().equals(username) && user.getPassword().equals(password)){
				return true;
			}
		}
		return false;
	}

    public boolean handleRootCommand(String command, Token token) {
        return false;
    }

    public void run() {
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
            Message msg = null;
            int count = 0;
            do {
                // read and print message
                msg = (Message) input.readObject();
                System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.getCommand());

            // Write an ACK back to the sender
            count++;
            ArrayList<Object> list = new ArrayList<Object>();
            list.add(new User("user1", "pass1", "group1"));
            output.writeObject(new Message("Received message #" + count, null, list));

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