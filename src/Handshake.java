import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class Handshake {

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    

    public static ArrayList<SecretKeySpec> clientInitiateHandshake(ObjectOutputStream output, ObjectInputStream input, PublicKey serverkey) throws Exception {
        int bitLength = 2048; // 1024, 2048
        SecureRandom rnd = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength, rnd); 
        BigInteger g = BigInteger.probablePrime(bitLength, rnd); 
        // specify parameters to use for the algorithm
        DHParameterSpec dhParams = new DHParameterSpec(p, g);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(dhParams, new SecureRandom());
        KeyPair clientPair = keyGen.generateKeyPair();
        KeyAgreement clientAgree = KeyAgreement.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);
        //initialize key agreement
        clientAgree.init(clientPair.getPrivate());

        //send the client's half of the shared secret
        ArrayList<Object> stuff = new ArrayList<Object>();
        stuff.add(clientPair.getPublic());
        stuff.add(p);
        stuff.add(g);
        Message clienthalf = new Message(null, null, stuff);
        output.writeObject(clienthalf);

        //receive server's half of shared secret, modify for other secrets
        byte[][] encryptedKeyPhrase = (byte[][]) input.readObject();
        Key servPublic = (Key)input.readObject();
        byte[] signature = (byte[]) input.readObject();
        clientAgree.doPhase(servPublic, true);
        byte[] secret = clientAgree.generateSecret();
         byte[] hmacsecret = Arrays.copyOf(secret, secret.length);
        int modified = secret[secret.length-1] + 1;
        byte last = (byte) modified;
        hmacsecret[secret.length-1] = last;
        
        MessageDigest Sha256 = MessageDigest.getInstance("SHA-256", "BC");
        byte[] hashedsecret = Sha256.digest(secret);
        byte[] hmacKeybytes = Sha256.digest(hmacsecret);
        hashedsecret = java.util.Arrays.copyOf(hashedsecret, 32);
        hmacKeybytes= java.util.Arrays.copyOf(hmacKeybytes, 32);
        // System.out.println(new String(hashedsecret)); //for debugging
        SecretKeySpec sharedSessionKey = new SecretKeySpec(hashedsecret, "AES");
        SecretKeySpec hmacKey = new SecretKeySpec(hmacKeybytes, "HmacSHA256");
        //test the new session key
        Message keyPhrase = SymmetricEncrypt.symmDecrypt(sharedSessionKey, encryptedKeyPhrase);
        String testDecryption = keyPhrase.getCommand();
        if(!testDecryption.equals("Bello!")){
            System.out.println("key generated but not the same as the server's key");
            return null;
        }

        //testing the server's signature
        if(!verifySig(signature, SymmetricEncrypt.serialize(servPublic), serverkey)){
            System.out.println("Server untrustworthy, ending handshake.");
            return null;
        }
        ArrayList<SecretKeySpec> retkeys = new ArrayList<SecretKeySpec>();
        retkeys.add(sharedSessionKey);
        retkeys.add(hmacKey);
        return retkeys; 
    }
    
    public static ArrayList<SecretKeySpec> serverInitiateHandshake(ObjectOutputStream output, ObjectInputStream input, AuthServer server) throws Exception{
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
        byte[] secret = servAgree.generateSecret(); //this is the shared secret

        // generate our modified secrets for our hmac keys and session IDs
        byte[] hmacsecret = Arrays.copyOf(secret, secret.length);
        int modified = secret[secret.length-1] + 1;
        byte last = (byte) modified;
        hmacsecret[secret.length-1] = last;

        MessageDigest Sha256 = MessageDigest.getInstance("SHA-256", "BC");
        byte[] hashedsecret = Sha256.digest(secret);
        byte[] hmacKeybytes = Sha256.digest(hmacsecret);
        hashedsecret = java.util.Arrays.copyOf(hashedsecret, 32);
        hmacKeybytes= java.util.Arrays.copyOf(hmacKeybytes, 32);
        // System.out.println(new String(hashedsecret)); //for debugging
        SecretKeySpec sharedSessionKey = new SecretKeySpec(hashedsecret, "AES");
        SecretKeySpec hmacKey = new SecretKeySpec(hmacKeybytes, "HmacSHA256");
        //confirm our new AES256 key with the client and send our half of the shared secret with signature
        String KeyPhrase = "Bello!";
        byte[][] encryptedKeyPhrase = SymmetricEncrypt.symmEncrypt(sharedSessionKey, new Message(KeyPhrase, null, null));
        output.writeObject(encryptedKeyPhrase);
        output.writeObject(servPair.getPublic());
        output.writeObject(sign(SymmetricEncrypt.serialize(servPair.getPublic()), server.getPrivateKey()));

        ArrayList<SecretKeySpec> retkeys = new ArrayList<SecretKeySpec>();
        retkeys.add(sharedSessionKey);
        retkeys.add(hmacKey);
        return retkeys;
    }
    
    public static ArrayList<SecretKeySpec> serverInitiateHandshake(ObjectOutputStream output, ObjectInputStream input, ResourceServer server) throws Exception{
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
        byte[] secret = servAgree.generateSecret(); //this is the shared secret

        // generate our modified secrets for our hmac keys and session IDs
        byte[] hmacsecret = Arrays.copyOf(secret, secret.length);
        int modified = secret[secret.length-1] + 1;
        byte last = (byte) modified;
        hmacsecret[secret.length-1] = last;

        MessageDigest Sha256 = MessageDigest.getInstance("SHA-256", "BC");
        byte[] hashedsecret = Sha256.digest(secret);
        byte[] hmacKeybytes = Sha256.digest(hmacsecret);
        hashedsecret = java.util.Arrays.copyOf(hashedsecret, 32);
        hmacKeybytes= java.util.Arrays.copyOf(hmacKeybytes, 32);
        // System.out.println(new String(hashedsecret)); //for debugging
        SecretKeySpec sharedSessionKey = new SecretKeySpec(hashedsecret, "AES");
        SecretKeySpec hmacKey = new SecretKeySpec(hmacKeybytes, "HmacSHA256");
        //confirm our new AES256 key with the client and send our half of the shared secret with signature
        String KeyPhrase = "Bello!";
        byte[][] encryptedKeyPhrase = SymmetricEncrypt.symmEncrypt(sharedSessionKey, new Message(KeyPhrase, null, null));
        output.writeObject(encryptedKeyPhrase);
        output.writeObject(servPair.getPublic());
        output.writeObject(sign(SymmetricEncrypt.serialize(servPair.getPublic()), server.getPrivateKey()));

        ArrayList<SecretKeySpec> retkeys = new ArrayList<SecretKeySpec>();
        retkeys.add(sharedSessionKey);
        retkeys.add(hmacKey);
        return retkeys;
    }

    public static byte[] sign(byte[] bytes, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");
        signature.initSign(privateKey);

        signature.update(bytes);

        return signature.sign();
    }

    static boolean verifySig (byte[] signature, byte[] signed, PublicKey pubkey){
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA/PSS", BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(pubkey); // replace with AS public key
            verifier.update(signed);
            return verifier.verify(signature);
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
            return false;
        }
    }
}
