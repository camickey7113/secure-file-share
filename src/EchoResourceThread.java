import java.lang.Thread; // We will extend Java's base Thread class
import java.net.Socket;
import java.io.IOException;
import java.io.ObjectInputStream; // For reading Java objects off of the wire
import java.io.ObjectOutputStream; // For writing Java objects to the wire

/**
 * A simple server thread. This class just echoes the messages sent
 * over the socket until the socket is closed.
 *
 * @author Adam J. Lee (adamlee@cs.pitt.edu)
 */
public class EchoResourceThread extends Thread {
    private final Socket socket; // The socket that we'll be talking over


    /**
     * Constructor that sets up the socket we'll chat over
     *
     * @param _socket The socket passed in from the server
     *
     */
    public EchoResourceThread(Socket _socket) {
        socket = _socket;
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
                msg = (Message) input.readObject();
                System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.theMessage);




                // HANDLE CLIENT REQUEST
                handleClientRequest(msg, output); // output is needed to send messages back to the client 





                // Write ackknowledgement back to sender // i want to ask him about this part why he had it there 
                count++;
                output.writeObject(new Message("file.txt"));

            } while (!msg.theMessage.toUpperCase().equals("EXIT"));

            // Close and cleanup
            System.out
                    .println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
            socket.close();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage()); 
            e.printStackTrace(System.err);
        }

    } // -- end run()



    // other methods

    // commands: read, write, create, delete
    // create and delete files, or create and delete users too if you're the root.

    private void handleClientRequest(Message msg, ObjectOutputStream output) throws IOException {
        String request = msg.theMessage; // like "read group1_file1.txt"
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

