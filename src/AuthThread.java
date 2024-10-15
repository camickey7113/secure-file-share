import java.lang.Thread;            
import java.net.Socket;
import java.io.ObjectInputStream;   
import java.io.ObjectOutputStream; 
import java.util.*;

public class AuthThread extends Thread
{
    private AuthServer server;
    private final Socket socket;

    public AuthThread(AuthServer server, Socket socket) {
        this.server = server;
        this.socket = socket;
    }

    public Token generateToken() {
        return null;
    }

    public boolean handleRootCommand(String command, Token token) {
        return false;
    }
    
    

    public void run()
    {
        try {
            // Print incoming message
            System.out.println("** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " **");

            // set up I/O streams with the client
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

            // Loop to read messages
            Message msg = null;
            int count = 0;
            do {
            // read and print message
            msg = (Message)input.readObject();
            System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.getCommand());

            // Write an ACK back to the sender
            count++;
            ArrayList<Object> list = new ArrayList<Object>();
            list.add(new User("user1", "pass1", "group1"));
            output.writeObject(new Message("Received message #" + count, null, list));

            } while(!msg.getCommand().toUpperCase().equals("EXIT"));

            // Close and cleanup
            System.out.println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
            socket.close();

        }
        catch(Exception e){
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

} 