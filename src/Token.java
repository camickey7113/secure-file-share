//import java.util.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class Token implements java.io.Serializable {

	private String group;
	private String username;
	private byte[] id; // for sha256 hash of the resource servers pub key
	private Instant timestamp;
	
	static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

	public Token(String username){
		this.username = username;
	}

	public Token(String username, String group) {
		this.username = username;
		this.group = group;
		this.timestamp = Instant.now().plus(Duration.ofHours(1));
	}

	public String getGroup() {
		return this.group;
	}

	public void setGroup(String group) {
		this.group = group;
	}	

	public String getUser(){
		return this.username;
	}

	public void setUser(String username){
		this.username = username;
	}

	public String toString() {
		return username + ":" + group + ":" + new String(id, StandardCharsets.UTF_8);
	}

	public void setId(PublicKey key) {
		this.id = hashServerKey(key);
	}
	
	public byte[] getId(){
		return id;
	}

	public boolean isExpired(){
		return Instant.now().isAfter(timestamp);
	}

	// takes a server ID and comapres it to the hashed version kept within the token
	public boolean checkServerID(PublicKey key) {
		return Arrays.equals(this.id, hashServerKey(key));
	}
	
	public byte[] hashServerKey(PublicKey key){
		try {
			byte[] keybytes = key.getEncoded();
			MessageDigest Sha256 = MessageDigest.getInstance("SHA-256", "BC");
			return Sha256.digest(keybytes);
		} catch (Exception e) {
			System.out.println("Error hashing server key: " + e.getMessage());
			return null;
		}
	}

}