//import java.util.*;

public class Token implements java.io.Serializable {

	private String group;
	private String username;

	public Token(String group, String username) {
		this.group = group;
		this.username = username;
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
}