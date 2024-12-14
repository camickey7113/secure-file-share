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
    private int resCounter;
    private ObjectInputStream input;
    private ObjectOutputStream output;
    private SecretKeySpec hmacKey;

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
        this.resCounter = 0;
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
        byte[][] encryptedKeyPhrase = SymmetricEncrypt.symmEncrypt(sharedSessionKey, new Message(KeyPhrase, null, null));
        output.writeObject(encryptedKeyPhrase);
        output.writeObject(servPair.getPublic());
        output.writeObject(sign(SymmetricEncrypt.serialize(servPair.getPublic()), server.getPrivateKey()));


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

            // // set up I/O streams with the client
            input = new ObjectInputStream(socket.getInputStream());
            output = new ObjectOutputStream(socket.getOutputStream());


            //diffiehellman bullshit
            ArrayList<SecretKeySpec> ret = Handshake.serverInitiateHandshake(output, input, server);
            SecretKeySpec AESkey = ret.get(0);
            hmacKey = ret.get(1);
            // Loop to read messages
            Message msg = null;
            int count = 0;
            do {
                // new decryption
                byte[][] nonsense = (byte[][]) input.readObject();
                //msg = SymmetricEncrypt.symmDecrypt(AESkey, nonsense);
                msg = receiveMessage(AESkey, nonsense);
                // if msg is null, they tryna hack us
                if (msg == null) break;

                System.out.println(msg.getCommand());
                // // Write an ACK back to the sender
                output.flush();
                System.out.println("Handling client request...");
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
            //return;
        }
        // check timestamp
        if (t.isExpired()) {
            System.out.println("Token is expired...");
            sendMessage(AESkey, new Message("logout", null, null));
            return;
        }
        // check session ID
        if (!t.checkServerID(server.getPublicKey())) {
            System.out.println("Stolen token...");
            return;
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
                        // if no files found
                        if (filesList.length == 0) {
                            stuff.add("No files found...");
                        } else {
                            for(File f : filesList){
                                System.out.println("check 2");
                                if(f.isFile()){
                                    // System.out.println(f.getName());
                                    stuff.add(f.getName());
                                }
                            }
                        }
                    
                        System.out.println("Sending back list message...");
                        sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
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
                            byte[][] contentsIV = (byte[][]) msg.getStuff().get(1);
                            try (FileOutputStream fos = new FileOutputStream(file)) {
                                fos.write(contentsIV[0]);
                                fos.write(contentsIV[1]);
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            stuff.add(true);
                            sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                        } catch(Exception e) {
                            stuff.add(false);
                            sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                        }
                        break;
    
                    case "download":
                        try {
                            // Search user's group folder for file
                            File file = new File("group" + File.separator + t.getGroup() + File.separator + msg.getStuff().get(0));
                            System.out.println(file.getAbsolutePath());
                            byte[] fileData = new byte[(int) file.length()];
                            // Use FileInputStream to read the file into the byte array                            
                            try (FileInputStream fos = new FileInputStream(file)) {
                                // int bytesRead = 0;
                                // fos.read(fileData, 0, 16);
                                // int num = fos.read(fileData[1], 0, fileData[1].length);
                                // System.out.println(num);
                                // System.out.println(fileData[0].length);
                                // System.out.println(fileData[1].length);
                                int num = fos.read(fileData);
                                // for(int i = 0; i < fileData[1].length; i++){
                                //     System.out.print(fileData[1][i] + " ");
                                // }
                                // System.out.println();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            stuff.add(true);
                            stuff.add(msg.getStuff().get(0));
                            stuff.add(fileData);
                            sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                        } catch (Exception e) {
                            e.printStackTrace();
                            stuff.add(false);
                            sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
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
                        sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                        ;
                        break;
    
                    default:
                        stuff.add(false);
                        sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                        break;
                }
            } else {
                switch(msg.getCommand()){ //if we aren't receiving a verified signature, check if the command is a root command
                    case "collect":
                    String directoryPath = "group" + File.separator + msg.getStuff().get(0);
                    File directory = new File(directoryPath);
                    boolean directoryCreated = directory.mkdir();
                    stuff.add(true);

                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
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
                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
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

                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                    break;
                default:
                    stuff.add(false);
                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
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

    public void sendMessage(SecretKey reskey, Message m) {
        // set counter
        m.setCounter(++resCounter);
        // set hmac
        m.setHMAC(hmacKey);
        // encrypt message
        byte[][]encryptedStuff = SymmetricEncrypt.symmEncrypt(reskey, m);
        // send message
        try {
            output.writeObject(encryptedStuff);
        } catch (Exception e) {
            System.out.println("Error sending message: " + e.getMessage());
        }
    }

    public Message receiveMessage(SecretKeySpec resKey, byte[][] encryptedMessage) {
        // decrypt
        Message m = SymmetricEncrypt.symmDecrypt(resKey, encryptedMessage);
        // check counter
        if(++resCounter != m.getCounter()) {
            System.out.println("Something's fishy...(counter)");
        }
        // check HMAC
        if (!m.checkHMAC(hmacKey)) {
            System.out.println("Something's fishy...(hmac)");
        }
        // check timestamp
        if (m.getToken().isExpired()) {
            System.out.println("Token is expired...");
        }
        return m;
   }
} // -- end class ResourceThread
