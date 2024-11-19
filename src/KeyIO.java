import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyIO {

    // Write key bytes to file
    public static void writeKeyToFile(String fileName, byte[] keyBytes) throws IOException {
        String keyString = Base64.getEncoder().encodeToString(keyBytes);
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(keyString.getBytes());
        } catch (Exception e) {
            System.out.println("writeKeyToFile : " + e.getMessage());
        }
    }

    // Read key bytes from file
    public static PrivateKey readPrivateKeyFromFile(String fileName) throws IOException {
        File file = new File(fileName);
        byte[] fileBytes = new byte[(int) file.length()];
        try {
            FileInputStream fis = new FileInputStream(file);
            fis.read(fileBytes);

            String keyString = new String(fileBytes);
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyString));
            return KeyFactory.getInstance("RSA").generatePrivate(privateSpec);
        } catch (Exception e) {
            System.out.println("readPrivateKeyFromFile : " + e.getMessage());
            return null;
        }
    }

    // Read key bytes from file
    public static PublicKey readPublicKeyFromFile(String fileName) throws IOException {
        File file = new File(fileName);
        byte[] fileBytes = new byte[(int) file.length()];
        try {
            FileInputStream fis = new FileInputStream(file);
            fis.read(fileBytes);

            String keyString = new String(fileBytes);
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(Base64.getDecoder().decode(keyString));
            return KeyFactory.getInstance("RSA").generatePublic(publicSpec);
        } catch (Exception e) {
            System.out.println("readPublicKeyFromFile : " + e.getMessage());
            return null;
        }
    }
}
