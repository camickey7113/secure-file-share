import java.lang.Thread; // We will extend Java's base Thread class
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream; // For reading Java objects off of the wire
import java.io.ObjectOutputStream; // For writing Java objects to the wire
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ResourceThread extends Thread {
    private ResourceServer server;
    private final Socket socket; // The socket that we'll be talking over
    private Message msg;


    public static final byte[] encodedDemoKey = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);


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
                // new decryption
                byte[][] nonsense = (byte[][]) input.readObject();
                SecretKeySpec AESkey = new SecretKeySpec(encodedDemoKey, "AES");
                msg = symmDecrypt(AESkey, nonsense);



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
            SecretKeySpec AESkey = new SecretKeySpec(encodedDemoKey, "AES");
            byte[][] encryptedStuff;
            switch (msg.getCommand()) {
                case "list":
                    ProcessBuilder pb = new ProcessBuilder("bash", "-c", "cd /src/group" + File.separator +  t.getGroup() + "; ls");
                    Process process = pb.start();
                    stuff.add(new String(process.getInputStream().readAllBytes()));
                    System.out.println("Sending back list message...");
                    encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                    output.writeObject(encryptedStuff);

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
                        encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                        output.writeObject(encryptedStuff);
                    } catch(Exception e) {
                        stuff.add(false);
                        encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                        output.writeObject(encryptedStuff);
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
                        encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                        output.writeObject(encryptedStuff);
                    } catch (Exception e){
                        stuff.add(false);
                        encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                        output.writeObject(encryptedStuff);
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
                    encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                    output.writeObject(encryptedStuff);
                    break;

                case "collect":
                    String directoryPath = "group" + File.separator + msg.getStuff().get(0);
                    File directory = new File(directoryPath);
                    boolean directoryCreated = directory.mkdir();
                    stuff.add(true);
                    encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                    output.writeObject(encryptedStuff);
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
                    encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                    output.writeObject(encryptedStuff);
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
                    encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                    output.writeObject(encryptedStuff);
                    break;

                case "null":
                    stuff.add(false);
                    encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                    output.writeObject(encryptedStuff);
                    break;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        
    }

    //New Symmetric Encryption Stuff ------------------------------------------------------------------------------------------
    //Symmetric Encryption
    public static byte[][] symmEncrypt(SecretKey AESkey, Message msg){
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher aesc;
        try {
            aesc = Cipher.getInstance("AES/CBC/PKCS7Padding", BouncyCastleProvider.PROVIDER_NAME);
            aesc.init(Cipher.ENCRYPT_MODE, AESkey);
            byte[] nonsense = serialize(msg);
            byte[][] ret = {aesc.getIV(), aesc.doFinal(nonsense)};
            return ret;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } 
    }

    //Symmetric Decryption
    public static Message symmDecrypt(SecretKey AESkey, byte[][] encryptedStuff){
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher aesc;
        try {
            aesc = Cipher.getInstance("AES/CBC/PKCS7Padding", BouncyCastleProvider.PROVIDER_NAME);
            aesc.init(Cipher.DECRYPT_MODE, AESkey, new IvParameterSpec(encryptedStuff[0]));
            byte[] decrypted = aesc.doFinal(encryptedStuff[1]);
            return (Message) deserialize(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        
    }

    //takes a generic serializable object and then turns it into a byte array for encryption
    public static byte[] serialize(Object obj){ 
        try(ByteArrayOutputStream b = new ByteArrayOutputStream()){
            try(ObjectOutputStream o = new ObjectOutputStream(b)){
                o.writeObject(obj);
            } catch (Exception e){
                System.out.println("Error during serialization: "+ e.getMessage());
                return null;
            }
            return b.toByteArray();
        } catch (Exception e){
            System.out.println("Error during serialization: "+ e.getMessage());
            return null;
        }
    }

    //takes in a byte stream and returns a generic object 
    public static Object deserialize(byte[] nonsense) throws IOException, ClassNotFoundException{
        try(ByteArrayInputStream b = new ByteArrayInputStream(nonsense)){
            try(ObjectInputStream i = new ObjectInputStream(b)){
                return i.readObject();
            } catch (Exception e){
                System.out.println("Error during deserialization: "+ e.getMessage());
                return null;
            }
        } catch (Exception e){
            System.out.println("Error during deserialization: "+ e.getMessage());
            return null;
        }
    }



} // -- end class ResourceThread
