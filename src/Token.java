import java.util.*;

public class Token implements java.io.Serializable {

	private String group;
	private String username;

	public Token(String username){
		this.username = username;
	}

	public Token(String username, String group) {
		this.username = username;
		this.group = group;
	}

	public String getGroup() {
		return this.group;
	}

	public void setGroup(String group) {
		this.group = group;
	}	
}