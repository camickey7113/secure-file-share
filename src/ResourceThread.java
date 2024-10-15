import java.lang.Thread; // We will extend Java's base Thread class
import java.net.Socket;
import java.io.IOException;
import java.io.ObjectInputStream; // For reading Java objects off of the wire
import java.io.ObjectOutputStream; // For writing Java objects to the wire
import java.util.*;

public class ResourceThread extends Thread {
    private ResourceServer server;
    private final Socket socket; // The socket that we'll be talking over
    private Message msg;

    /**
     * Constructor that sets up the socket we'll chat over
     *
     * @param socket The socket passed in from the server
     *
     */
    
    public ResourceThread(ResourceServer server, Socket socket) {
        this.server = server;
        this.socket = socket;
    }

    /**
     * run() is basically the main method of a thread. This thread
     * simply reads Message objects off of the socket.
     *
     */
    public void run() {
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
            // System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.getCommand());



            // // Write an ACK back to the sender
            ArrayList<Object> stuff = new ArrayList<Object>();
            if (msg.getCommand().equals("list")) {
                ProcessBuilder pb = new ProcessBuilder("bash", "-c", "cd group ; ls");
                Process process = pb.start();
                stuff.add(new String(process.getInputStream().readAllBytes()));
            }
            output.writeObject(new Message(msg.getCommand(), null, stuff));



            }
            while (!msg.getCommand().equals("logout"));

            // Close and cleanup
            System.out.println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
            socket.close();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage()); 
            e.printStackTrace(System.err);
        }
    }

    // other methods

    // commands: read, write, create, delete, list(ls)
    // create and delete files 

    private void handleClientRequest(Message msg, ObjectOutputStream output) throws IOException {
        String request = msg.getCommand(); // like "read group1_file1.txt"
        String command = request.split(" ")[0]; // like "read"
        String fileName = request.split(" ")[1]; // like "group1_file1.txt"

        // if command was "read", OR you are root
            // immediately call a "performOperation()" type of function bc anybody can read anything ... or if you're the root, you can DO anything

        // else if command was not read.. so write, create, or delete a file
        // btw if this hits, you are definitely a student
            // if you are a part of the group that the file is stored at, call "performOperation()"
            // else, throw an exception "ur not a part of this group, cant do it"
    
    }
    
} // -- end class EchoResourceThread





