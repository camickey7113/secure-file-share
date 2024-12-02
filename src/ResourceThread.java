import java.lang.Thread; // We will extend Java's base Thread class
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream; // For reading Java objects off of the wire
import java.io.ObjectOutputStream; // For writing Java objects to the wire
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.util.PublicKeyFactory;


public class ResourceThread extends Thread {
    private ResourceServer server;
    private final Socket socket; // The socket that we'll be talking over
    private Message msg;


    // public static final byte[] encodedDemoKey = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

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

    

    public static byte[] sign(byte[] hashedToken, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");
        signature.initSign(privateKey);

        signature.update(hashedToken);

        return signature.sign();
    }

    public SecretKeySpec serverInitiateHandshake(ObjectOutputStream output, ObjectInputStream input) throws Exception{
        //retreive client half of handshake
        Message clienthalf = (Message) input.readObject();
        Key clientPublic = (Key) clienthalf.getStuff().get(0);
        BigInteger p = (BigInteger) clienthalf.getStuff().get(1);
        BigInteger g = (BigInteger) clienthalf.getStuff().get(2);

        //generate servers half of the secret
        DHParameterSpec dhParams = new DHParameterSpec(p, g);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        keyGen.initialize(dhParams, new SecureRandom());
        KeyPair servPair = keyGen.generateKeyPair();
        KeyAgreement servAgree = KeyAgreement.getInstance("DH", "BC");

        //generate the shared secret
        servAgree.init(servPair.getPrivate());
        servAgree.doPhase(clientPublic, true);
        byte[] secret = servAgree.generateSecret();
        MessageDigest Sha256 = MessageDigest.getInstance("SHA-256", "BC");
        byte[] hashedsecret = Sha256.digest(secret);
        hashedsecret = java.util.Arrays.copyOf(hashedsecret, 32);
        // System.out.println(new String(hashedsecret)); 
        SecretKeySpec sharedSessionKey = new SecretKeySpec(hashedsecret, "AES");
        
        //confirm our new AES256 key with the client and send our half of the shared secret with signature
        String KeyPhrase = "Bello!";
        byte[][] encryptedKeyPhrase = symmEncrypt(sharedSessionKey, new Message(KeyPhrase, null, null));
        output.writeObject(encryptedKeyPhrase);
        output.writeObject(servPair.getPublic());
        output.writeObject(sign(serialize(servPair.getPublic()), server.getPrivateKey()));


        return sharedSessionKey;
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


            //diffiehellman bullshit
            SecretKeySpec AESkey = serverInitiateHandshake(output, input);

            // Loop to read messages
            Message msg = null;
            int count = 0;
            do {
                // new decryption
                byte[][] nonsense = (byte[][]) input.readObject();
                msg = symmDecrypt(AESkey, nonsense);



                // System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() +
                // "] " + msg.getCommand());
                System.out.println(msg.getCommand());
                // // Write an ACK back to the sender
                output.flush();
                handleClientRequest(msg, output, AESkey);
                output.flush();

            } while (!msg.getCommand().equals("exit"));
            
            // cleanup
            socket.close();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }


    private void handleClientRequest(Message msg, ObjectOutputStream output, SecretKeySpec AESkey) throws IOException {
        ArrayList<Object> stuff = new ArrayList<Object>();
        Token t = msg.getToken();
        byte[][] encryptedStuff;
        // check signature before proceeding
        boolean verified;
        if(t == null) {
            verified = false;
        } else {
            verified = verify(t, msg.getSignature());
        }
        if (!verified) {
            System.out.println("Signature not verified.");
        }

        try {
            if(verified){
                switch (msg.getCommand()) {
                    case "list":
                        // ProcessBuilder pb = new ProcessBuilder("bash", "-c", "cd /src/group" + File.separator +  t.getGroup() + "; ls");
                        // Process process = pb.start();
                        // stuff.add(new String(process.getInputStream().readAllBytes()));

                        File curDir = new File("./group/" + t.getGroup());
                        File[] filesList = curDir.listFiles();
                        for(File f : filesList){
                            if(f.isFile()){
                                // System.out.println(f.getName());
                                stuff.add(f.getName());
                            }
                        }

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
                            System.out.println(file.getAbsolutePath());
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
    
                    default:
                        stuff.add(false);
                        encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                        output.writeObject(encryptedStuff);
                        break;
                }
            } else {
                switch(msg.getCommand()){ //if we aren't receiving a verified signature, check if the command is a root command
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

                    System.out.println(directoryPath3);

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
                default:
                    stuff.add(false);
                    encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, stuff));
                    output.writeObject(encryptedStuff);
                    break;
                }
            }
            // encryptedStuff = symmEncrypt(AESkey, new Message(msg.getCommand(), null, msg.getSignature(), stuff));
            // output.writeObject(encryptedStuff);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    boolean verify(Token t, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA/PSS", "BC");
            verifier.initVerify(server.getAuthKey()); // replace with AS public key
            verifier.update(hashToken(t));
            return verifier.verify(signature);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    public byte[] hashToken(Token t) {
        try {
            MessageDigest mdig = MessageDigest.getInstance("SHA-256");
            return mdig.digest(t.toString().getBytes());
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
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
