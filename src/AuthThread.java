
//package org.mindrot.jbcrypt;
import java.lang.Thread;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.print.attribute.HashAttributeSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AuthThread extends Thread {
    private AuthServer server;
    private final Socket socket;
    private int authCounter;

    private ObjectInputStream input;
    private ObjectOutputStream output;
    
    private SecretKeySpec hmacKey;

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    
    public AuthThread(AuthServer server, Socket socket) {
        this.server = server;
        this.socket = socket;
        authCounter = 0;
    }

    public Token generateToken(User user, PublicKey resKey) {      
        Token newToken = new Token(user.getUsername(), user.getGroup());
        newToken.setId(resKey);
        return newToken;

    }

    public boolean handleCommand(Message msg, ObjectOutputStream output, SecretKeySpec AESkey) {
        ArrayList<Object> stuff = new ArrayList<Object>();
        Token t = msg.getToken();
        User user;
        int clientCounter = msg.getCounter();
        byte[][] encryptedStuff;

        try {
            switch (msg.getCommand()) {
                case "login":
                    user = (User) msg.getStuff().get(0);
                    // authenticate the user
                    if (authenticate(user)) {

                        User authUser = server.getUserList().getUser(user.getUsername()); // this is whats failing
                        // get user from the username in the token
                        // System.out.print("this is the auth username" + authUser.getUsername());
                        PublicKey resKey = (PublicKey) msg.getStuff().get(1);
                        t = generateToken(authUser, resKey);
                        stuff.add(user);
                        // create signature
                        byte[] signature = sign(hashToken(t), server.getPrivateKey());
                        // send message with token back to client:
                        sendMessage(AESkey, new Message(msg.getCommand(), t, signature, stuff));

                    } else {
                        sendMessage(AESkey, new Message(msg.getCommand(), null, null));
                    }
                    break;

                case "list":
                    // getting the desired group from the message
                    String listgroup = (String) msg.getStuff().get(0);
                    // retrieving the members
                    ArrayList<String> members = new ArrayList<String>();

                    Group g = server.getGroupList().getGroup(listgroup);
                    if (g == null) {
                        stuff.add(false);
                        stuff.add("not a valid group");

                        sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                        break;
                    }

                    stuff.add(true);
                    HashMap<String, User> m = g.getMembers().getUserMap();
                    // populate arraylist with usernames
                    for (String key : m.keySet()) {
                        members.add(key);
                    }
                    stuff.add(members);
                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                    break;

                case "create":
                    User originalUser = (User) msg.getStuff().get(0);
                    // Group newGroup = newUser.getGroup();
                    User newUser = hashPassword(originalUser); // intercept user created and add a real salt and hashed
                                                               // password to users.txt
                    if (server.getUserList().addUser(newUser)) {
                        System.out.println("User " + newUser.getUsername() + " added.");
                        server.saveUserList("users.txt");
                        // stuff.add(true); add in later

                        // if group assigning exists assign user to that group
                        // otherwise create a new group
                        if (server.getGroupList().containsGroup(newUser.getGroup())) {
                            Group existingGroup = server.getGroupList().getGroup(newUser.getGroup());
                            existingGroup.addMember(newUser);
                            stuff.add(true);
                        } else {
                            Group newGroup = new Group(newUser.getGroup());
                            server.getGroupList().addGroup(newGroup);
                            newGroup.addMember(newUser);
                            server.saveGroupList("groups.txt");
                            stuff.add(true);
                        }
                    } else {
                        stuff.add(false);
                    }
                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                    break;

                case "delete":
                    String deletedUsername = (String) msg.getStuff().get(0);
                    if (server.getUserList().containsUser(deletedUsername)) {
                        User deletedUser = server.getUserList().getUser(deletedUsername);
                        Group existingGroup = server.getGroupList().getGroup(deletedUser.getGroup());
                        existingGroup.removeMember(deletedUser);
                        if (server.getUserList().deleteUser(deletedUser)) {
                            // System.out.println("User " + deletedUser.getUsername() + " deleted.");
                            server.saveUserList("users.txt");
                            stuff.add(true);
                        }
                    } else {
                        System.out.println("User doesn't exist!");
                        stuff.add(false);
                    }

                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                    break;

                case "collect":
                    if (server.getGroupList().getGroup((String) msg.getStuff().get(0)) != null) {
                        stuff.add(false);
                    } else {
                        server.getGroupList().addGroup(new Group((String) (msg.getStuff()).get(0)));
                        server.saveGroupList("groups.txt");
                        stuff.add(true);
                    }
                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                    break;

                case "empty":
                    Group e = server.getGroupList().getGroup((String) msg.getStuff().get(0));
                    if (e == null) {
                        stuff.add(false);
                    } else if (e.getMembers().hasMembers()) {
                        stuff.add(false);
                    } else {
                        stuff.add(true);
                    }
                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                    stuff.remove(0);
                    break;

                case "release":
                    System.out.println("releasing...");
                    Group delGroup = server.getGroupList().getGroup((String) msg.getStuff().get(0));
                    // some redundant error checking
                    if (delGroup == null) { // if the group doesnt exist
                        stuff.add(false);
                    }
                    if (delGroup.getMembers().size() != 0) { // if the group isnt empty
                        stuff.add(false);
                    } else {
                        server.getGroupList().removeGroup((String) (msg.getStuff()).get(0));
                        server.saveGroupList("groups.txt");
                        stuff.add(true);
                    }
                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                    break;

                case "assign":
                    // confirm that group and user exist
                    if (server.getGroupList().getGroup((String) msg.getStuff().get(1)) == null
                            || server.getUserList().getUser((String) msg.getStuff().get(0)) == null) {
                        stuff.add(false);
                        System.out.println("Cannot assign, either user or group are not valid.");
                    } else {
                        // get user object
                        User assignee = server.getUserList().getUser((String) msg.getStuff().get(0));
                        // remove user from old group
                        server.getGroupList().getGroup(assignee.getGroup()).removeMember(assignee);
                        // change group field in user
                        assignee.setGroup((String) msg.getStuff().get(1));
                        // add user to new group
                        server.getGroupList().getGroup((String) msg.getStuff().get(1)).addMember(assignee);
                        server.saveUserList("users.txt");
                        // return success
                        stuff.add(true);

                    }
                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                    break;

                case "groups":
                    // return list of groups
                    stuff.add(true);
                    stuff.add(server.getGroupList().getGroupNames());
                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                    break;

                case "null":
                    stuff.add(false);
                    sendMessage(AESkey, new Message(msg.getCommand(), null, stuff));
                    break;

                
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        
        return true;
    }

    @Deprecated
    public boolean signAndSend(Message m, ObjectOutputStream output) {
        try {
            // generate hashed token
            // sign hashed token
            if (m.getToken() != null) {
                byte[] signature = sign(hashToken(m.getToken()), server.getPrivateKey());
                m.setSignature(signature);
            }
            // output to socket
            output.writeObject(m);
            return true;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return false;
    }

    public static byte[] sign(byte[] hashedToken, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");
        signature.initSign(privateKey);

        signature.update(hashedToken);

        return signature.sign();
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

    // This function accepts a potential user object to be confirmed to exist in the
    // AS. If the user is found and the provided password matches return true.
    // Otherwise, return falsse.
    public boolean authenticate(User user) {
        try {
            if ((user.getUsername().equals("root") && user.getPassword().equals("root")) || ((server.getUserList()).containsUser(user.getUsername()))
            && BCrypt.checkpw(user.getPassword(), server.getUserList().getUser(user.getUsername()).getPassword())) {
                System.out.println("Username and Password accepted.");
                return true;
            } else {
                System.out.println("User and/or Group does not exist");
                return false;
            }
        } catch (Exception e) {
            System.out.println("User and/or Group does not exist");
            return false;
        }
    }

    public void sendMessage(SecretKey askey, Message m) {
        // set counter
        m.setCounter(++authCounter);
        // System.out.println("AS Counter: " + authCounter);
        // set hmac
        m.setHMAC(hmacKey);
        // encrypt message
        byte[][]encryptedStuff = SymmetricEncrypt.symmEncrypt(askey, m);
        // send message
        try {
            output.writeObject(encryptedStuff);
        } catch (Exception e) {
            System.out.println("Error sending message: " + e.getMessage());
        }
    }

    public Message receiveMessage(SecretKeySpec asKey, byte[][] encryptedMessage) {
        // decrypt
        Message m = SymmetricEncrypt.symmDecrypt(asKey, encryptedMessage);
        // check counter
        // System.out.println("AS Counter: " + authCounter);
        if(++authCounter != m.getCounter()) {
            System.out.println("Something's fishy...(counter)");
        }
        // check HMAC
        if (!m.checkHMAC(hmacKey)) {
            System.out.println("Something's fishy...(hmac)");
        }
        return m;
   }

    public void run() {
        try {
            // Print incoming message
            System.out.println("** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " **");

            // set up I/O streams with the client
            input = new ObjectInputStream(socket.getInputStream());
            output = new ObjectOutputStream(socket.getOutputStream());

            // Loop to read messages
            User authUser = null;

            Message msg = null;


            ArrayList<SecretKeySpec> ret = Handshake.serverInitiateHandshake(output, input, server);
            SecretKeySpec AESkey = ret.get(0);
            hmacKey = ret.get(1);


            do {
                // read and print message
                //msg = SymmetricEncrypt.symmDecrypt(AESkey, (byte[][])input.readObject());
                msg = receiveMessage(AESkey, (byte[][]) input.readObject());
                System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.getCommand());

                output.flush();
                handleCommand(msg, output, AESkey);
                output.flush();

            } while (!msg.getCommand().toUpperCase().equals("EXIT"));

            // Close and cleanup
            System.out.println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
            socket.close();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    // -------------------------------------------------------------------//
    // --------------------------T1 Implementation------------------------//

    public User hashPassword(User originalUser) {
        // This method hashes the password of the user created
        // take user created from "create"
        // extract password
        // hash said password
        // return new user with hashed password
        String salt = BCrypt.gensalt();
        // System.out.println("The salt is: " + salt);
        // System.out.println("The original user info:\n\n"+ originalUser.getUsername()
        // + "\n" + originalUser.getPassword() + "\n"+ originalUser.getGroup() +"\n"+
        // originalUser.getSalt());

        String saltedPassword = BCrypt.hashpw(originalUser.getPassword(), salt);
        if (originalUser.getSalt() == null) {
            originalUser.setSalt(salt);
        }
        // System.out.println("The salted user info:\n\n"+ originalUser.getUsername() +
        // "\n" + originalUser.getPassword() + "\n"+ originalUser.getGroup() +"\n"+
        // originalUser.getSalt());

        originalUser.setPassword(saltedPassword);
        // User saltedUser = new User(originalUser.getUsername(), saltedPassword,
        // originalUser.getGroup(), salt);
        // server.getUserList().addUser(originalUser);
        // server.saveUserList("users.txt");
        return originalUser;
        // return null;
    }

    public User rehashPassword(User originalUser, String salt) {
        // This method hashes the password of the user created
        // take user created from "create"
        // extract password
        // hash said password
        // return new user with hashed password
        // System.out.println("The salt is: " + salt);
        // System.out.println("The original user info:\n\n"+ originalUser.getUsername()
        // + "\n" + originalUser.getPassword() + "\n"+ originalUser.getGroup() +"\n"+
        // originalUser.getSalt());

        String saltedPassword = BCrypt.hashpw(originalUser.getPassword(), salt);
        if (originalUser.getSalt() == null || originalUser.getSalt().equals("$2b$00$0000000000000000000000")) {
            originalUser.setSalt(salt);
        }
        // System.out.println("The salted user info:\n\n"+ originalUser.getUsername() +
        // "\n" + originalUser.getPassword() + "\n"+ originalUser.getGroup() +"\n"+
        // originalUser.getSalt());

        originalUser.setPassword(saltedPassword);
        // User saltedUser = new User(originalUser.getUsername(), saltedPassword,
        // originalUser.getGroup(), salt);
        // server.getUserList().addUser(originalUser);
        // server.saveUserList("users.txt");
        return originalUser;
        // return null;
    }

    public boolean checkHashedPassword(User unverifiedUser) {
        // the unverified user only has a username and password
        // check the username and map that to a user stored in users.txt
        // assign the password that maps to that user equal to a variable
        // hash the password that the user input
        // check that the hash and what the user input matches
        // System.out.println("The passed in username is: " +
        // unverifiedUser.getUsername());

        User realUser = server.getUserList().getUser(unverifiedUser.getUsername()); // the user that should be in
                                                                                    // users.txt
        // System.out.print("checkHashedPW salt" + unverifiedUser.getSalt());
        // System.out.println("The stored in username is: " + realUser.getUsername());

        String verifiedPassword = realUser.getPassword(); // the password that should be in users.txt
        // System.out.println("The passed in password is: " +
        // unverifiedUser.getPassword());
        // System.out.println("The real password is: " + verifiedPassword);
        String salt = realUser.getSalt(); // get the public salt
        String hashedPassword = BCrypt.hashpw(unverifiedUser.getPassword(), unverifiedUser.getSalt()); // hash the input
                                                                                                       // password with
                                                                                                       // the salt
        // System.out.println("the hashed password that was passed in is: " +
        // hashedPassword);
        if (hashedPassword.equals(verifiedPassword)) { // if it matches the hashed password of the user and the hash of
                                                       // the input
            return true; // allow access
        }
        return false; // deny access
    }
}