import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;


import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class SymmetricEncrypt {
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
    
    public static byte[][] encryptFile(SecretKey AESkey, File f) throws IOException{
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher aesc;


        byte[] fileData = new byte[(int) f.length()];
        // Use FileInputStream to read the file into the byte array
        try (FileInputStream fileInputStream = new FileInputStream(f)) {
            int bytesRead = fileInputStream.read(fileData);
            if (bytesRead != fileData.length) {
                throw new IOException("Could not read the entire file into the byte array.");
            }
        }

        try {
            aesc = Cipher.getInstance("AES/CBC/PKCS7Padding", BouncyCastleProvider.PROVIDER_NAME);
            aesc.init(Cipher.ENCRYPT_MODE, AESkey);
            byte[][] ret = {aesc.getIV(), aesc.doFinal(fileData)};
            return ret;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    public static byte[] decryptToBytes(SecretKey AESkey, byte[][] encryptedStuff){
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher aesc;
        try {
            aesc = Cipher.getInstance("AES/CBC/PKCS7Padding", BouncyCastleProvider.PROVIDER_NAME);
            aesc.init(Cipher.DECRYPT_MODE, AESkey, new IvParameterSpec(encryptedStuff[0]));
            byte[] decrypted = aesc.doFinal(encryptedStuff[1]);
            return decrypted;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
       
    }

    // takes a generic serializable object and then turns it into a byte array for encryption
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


    // takes in a byte stream and returns a generic object
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
}