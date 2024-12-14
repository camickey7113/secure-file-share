import java.security.Security;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

// VERSION is 0-INDEXED!!!
public class GroupKey {
    // list of all keys that have existed for the group, in order of creation
    ArrayList<byte[]> history;

    public GroupKey() {
        // initialize history
        history = new ArrayList<byte[]>();
        // create first key
        newVersion();
    }

    public void newVersion() {
        history.add(generateKey());
    }

    public byte[] generateKey() {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            return secretKey.getEncoded();
        } catch (Exception e) {
            System.out.println("Error generating group key: " + e.getMessage());
            return null;
        }
    }

    // Returns the most recent gkey
    public byte[] getCurrentKey() {
        return history.getLast();
    }

    // Returns the key specified by the provided version
    public byte[] getKey(int i) {
        return history.get(i - 1);
    }

    // Returns the current version
    public int getVersion() {
        return history.size();
    }
}
