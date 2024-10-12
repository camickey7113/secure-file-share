import java.util.*;

public class Token implements java.io.Serializable {

	private String group;

	public Token(String group) {
		this.group = group;
	}

	public String getGroup() {
		return this.group;
	}

	public void setGroup(String group) {
		this.group = group;
	}	
}