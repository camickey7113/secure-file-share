import java.lang.Thread;
import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.security.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AuthThread extends Thread {
    private AuthServer server;
    private final Socket socket;

    public AuthThread(AuthServer server, Socket socket) {
        this.server = server;
        this.socket = socket;
    }

    private static SecretKey deriveAESKey(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] aesKeyBytes = sha256.digest(sharedSecret);
        return new SecretKeySpec(aesKeyBytes, 0, 16, "AES");
    }

    @Override
    public void run() {
        try {
            // Add BouncyCastle as a security provider
            Security.addProvider(new BouncyCastleProvider());
            System.out.println("** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " **");

            // Set up I/O streams with the client
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

            // Step 1: Generate DH parameters
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(2048);
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

            // Send DH parameters (p, g, l) individually
            output.writeObject(dhSpec.getP());
            output.writeObject(dhSpec.getG());
            output.writeObject(dhSpec.getL());
            output.flush();
            System.out.println("Sent DH parameters (p, g, l) to client.");

            // Step 2: Generate server's DH key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhSpec);
            KeyPair serverDHKeys = keyGen.generateKeyPair();
            PublicKey serverPublicKey = serverDHKeys.getPublic();

            // Step 3: Receive client's public DH key
            PublicKey clientPublicKey = (PublicKey) input.readObject();
            System.out.println("Received client's public DH key.");

            // Step 4: Derive the shared AES session key
            SecretKey aesKey = deriveAESKey(serverDHKeys.getPrivate(), clientPublicKey);
            System.out.println("Derived shared AES session key.");

            // Step 5: Sign and send server's public DH key
            Signature signer = Signature.getInstance("SHA256withRSA/PSS", "BC");
            signer.initSign(server.getPrivateKey());
            signer.update(serverPublicKey.getEncoded());
            byte[] signature = signer.sign();

            output.writeObject(serverPublicKey); // Send server's public DH key
            output.writeObject(signature);       // Send the signature
            output.flush();

            // Step 6: Encrypt and send confirmation message
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] confirmationMessage = cipher.doFinal("OK".getBytes());
            output.writeObject(confirmationMessage); // Send confirmation to client
            output.flush();
            System.out.println("Handshake complete. Secure communication established.");

            // Step 7: Handle incoming messages from the client
            Message msg;
            do {
                msg = (Message) input.readObject();
                System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.getCommand());
                handleCommand(msg, output); // Process the command
            } while (!msg.getCommand().equalsIgnoreCase("EXIT"));

            // Clean up
            System.out.println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
            socket.close();
        } catch (Exception e) {
            System.err.println("Error during handshake or message handling: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public boolean handleCommand(Message msg, ObjectOutputStream output) {
        // Existing handleCommand logic
        return true;
    }
}

