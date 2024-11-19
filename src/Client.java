import java.net.Socket;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.util.Scanner;

public class Client {
    // Set up I/O streams with the Auth server
    private static ObjectOutputStream authOutput;
    private static ObjectInputStream authInput;
    // Current user
    private static User currentUser;

    public static Scanner scanner = new Scanner(System.in);

    public static boolean connectToAuthServer() {
        System.out.print("Enter authentication server name: ");
        String AuthIP = scanner.next();
        System.out.print("Enter authentication server port: ");
        int AuthPortNumber = scanner.nextInt();

        try {
            Socket authSock = new Socket(AuthIP, AuthPortNumber);
            authOutput = new ObjectOutputStream(authSock.getOutputStream());
            authInput = new ObjectInputStream(authSock.getInputStream());
        } catch (Exception e) {
            System.out.println("Failed to connect to authentication server: " + e.getMessage());
            return false;
        }

        System.out.println("Connected to Authentication Server at " + AuthIP + ":" + AuthPortNumber);
        return true;
    }

    private static PublicKey getServerRSAPublicKey() throws Exception {
        String publicKeyPath = "server_public_key.der"; // Adjust to the actual file path
        FileInputStream fis = new FileInputStream(publicKeyPath);
        byte[] keyBytes = fis.readAllBytes();
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(keySpec);
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

    public static void performHandshake(ObjectOutputStream output, ObjectInputStream input) throws Exception {
        // Step 1: Receive DH parameters (p, g, l) from the server
        BigInteger p = (BigInteger) input.readObject();
        BigInteger g = (BigInteger) input.readObject();
        int l = (int) input.readObject();
        DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
        System.out.println("Reconstructed DH parameters from server.");

        // Step 2: Generate client's DH key pair using received parameters
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        KeyPair clientDHKeys = keyGen.generateKeyPair();
        PublicKey clientPublicKey = clientDHKeys.getPublic();

        // Step 3: Send client's public DH key to the server
        output.writeObject(clientPublicKey);
        output.flush();
        System.out.println("Sent client's public DH key to server.");

        // Step 4: Receive server's public DH key and its signature
        PublicKey serverPublicKey = (PublicKey) input.readObject();
        byte[] serverSignature = (byte[]) input.readObject();
        System.out.println("Received server's public DH key and signature.");

        // Step 5: Verify the server's identity using its pre-shared RSA public key
        PublicKey serverRSAPublicKey = getServerRSAPublicKey();
        Signature verifier = Signature.getInstance("SHA256withRSA/PSS");
        verifier.initVerify(serverRSAPublicKey);
        verifier.update(serverPublicKey.getEncoded());
        if (!verifier.verify(serverSignature)) {
            throw new SecurityException("Server verification failed!");
        }
        System.out.println("Server identity verified.");

        // Step 6: Derive the shared AES session key
        SecretKey aesKey = deriveAESKey(clientDHKeys.getPrivate(), serverPublicKey);
        System.out.println("Derived shared AES session key.");

        // Step 7: Receive and validate the server's confirmation message
        byte[] encryptedConfirmationMessage = (byte[]) input.readObject();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        String confirmation = new String(cipher.doFinal(encryptedConfirmationMessage));
        if (!"OK".equals(confirmation)) {
            throw new SecurityException("Session key confirmation failed!");
        }
        System.out.println("Handshake complete. Secure communication established.");
    }

    public static void main(String[] args) {
        if (connectToAuthServer()) {
            try {
                performHandshake(authOutput, authInput);
                System.out.println("Handshake successful with Authentication Server.");
            } catch (Exception e) {
                System.err.println("Handshake failed: " + e.getMessage());
                return;
            }
        } else {
            System.out.println("Failed to connect to the authentication server.");
            return;
        }

        // The rest of the application logic goes here
        while (true) {
            System.out.println("Please enter a command or type 'exit' to quit:");
            String input = scanner.next();
            if ("exit".equalsIgnoreCase(input)) {
                System.out.println("Exiting...");
                break;
            }
            // Handle additional commands here
        }
    }
}


