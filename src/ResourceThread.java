import java.lang.Thread; // We will extend Java's base Thread class
import java.net.Socket;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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
                msg = (Message) input.readObject();
                // System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() +
                // "] " + msg.getCommand());
                System.out.println(msg.getCommand());
                // // Write an ACK back to the sender
                handleClientRequest(msg, output);

            } while (!msg.getCommand().equals("exit"));
            
            // cleanup
            socket.close();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }


    private void handleClientRequest(Message msg, ObjectOutputStream output) throws IOException {
        ArrayList<Object> stuff = new ArrayList<Object>();
        Token t = msg.getToken();

        try {
            switch (msg.getCommand()) {
                case "list":
                    ProcessBuilder pb = new ProcessBuilder("bash", "-c", "cd group" + File.separator +  t.getGroup() + "; ls");
                    Process process = pb.start();
                    stuff.add(new String(process.getInputStream().readAllBytes()));
                    System.out.println("Sending back list message...");
                    output.writeObject(new Message(msg.getCommand(), null, stuff));

                    // File directory = new File("group" + File.separator + t.getGroup() + File.separator);
                    // if(directory.isDirectory()) {
                    //     String[] files = directory.list();
                    //     stuff.add(files);
                    // }
                    // System.out.println("Sending back list message...");
                    // output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "upload":
                    try {
                        File file = new File("group" + File.separator + t.getGroup() + File.separator + msg.getStuff().get(0));
                        file.createNewFile();

                        FileOutputStream fout = new FileOutputStream(file);
                        fout.write((byte[])msg.getStuff().get(1));

                        stuff.add(true);
                        output.writeObject(new Message(msg.getCommand(), null, stuff));
                    } catch(Exception e) {
                        stuff.add(false);
                        output.writeObject(new Message(msg.getCommand(), null, stuff));
                    }
                    break;

                case "download":
                    try {
                        // Search user's group folder for file
                        File file = new File("group" + File.separator + t.getGroup() + File.separator + msg.getStuff().get(0));
                        byte[] fileData = new byte[(int) file.length()];
                        // Use FileInputStream to read the file into the byte array
                        try (FileInputStream fileInputStream = new FileInputStream(file)) {
                            int bytesRead = fileInputStream.read(fileData);
                            if (bytesRead != fileData.length) {
                                throw new IOException("Could not read the entire file into the byte array.");
                            }
                        }
                        stuff.add(true);
                        stuff.add(msg.getStuff().get(0));
                        stuff.add(fileData);
                        output.writeObject(new Message(msg.getCommand(), null, stuff));
                    } catch (Exception e){
                        stuff.add(false);
                        output.writeObject(new Message(msg.getCommand(), null, stuff));
                    }
                    break;

                case "delete":
                    // Search user's group folder for file
                    File file = new File("group" + File.separator + t.getGroup() + File.separator + msg.getStuff().get(0));
                    if(file.isFile()) {
                        file.delete();
                        stuff.add(true);
                    } else {
                        stuff.add(false);
                    }
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "collect":
                    String directoryPath = "group" + File.separator + msg.getStuff().get(0);
                    File directory = new File(directoryPath);
                    boolean directoryCreated = directory.mkdir();
                    stuff.add(true);
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "release":
                    String directoryPath2 = "group" + File.separator + msg.getStuff().get(0);
                    File directory2 = new File(directoryPath2);
                    if(directory2.isDirectory()) {
                        for (File subfile : directory2.listFiles()) {
                            subfile.delete();
                        }
                        directory2.delete();
                        stuff.add(true);
                    } else {
                        stuff.add(false);
                    }
                    output.writeObject(new Message(msg.getCommand(), null, stuff));
                    break;

                case "create":
                    String newGroup = ((User)msg.getStuff().get(0)).getGroup();
                    // check if group folder exists
                    String directoryPath3 = "group" + File.separator + newGroup;
                    File directory3 = new File(directoryPath3);
                    // if it exists
                    if(!directory3.isDirectory()) {
                        // create directory
                        boolean directoryCreated3 = directory3.mkdir();
                        stuff.add(directoryCreated3); 
                    }
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

        
    }

} // -- end class ResourceThread
