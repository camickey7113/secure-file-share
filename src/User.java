//import java.io.Serializable;


public class User implements java.io.Serializable {
    private String username;
    private int salt;
    private String hashedPassword;
    private String group; 

    public User(String username, String hashedPassword, String group, int salt) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        
        // set group to null if the user is root. 
        if (username.equals("root")){
            this.group = null; // root user, no group 
            this.salt = 0;
        }
        else{
            this.group = group; //student 
            this.salt = salt;
        }

    }

    
    public String getUsername() {
        return this.username;
    }

    public int setSalt(int salt){
        return this.salt = salt;
    }
    public int getSalt() { 
        return this.salt; 
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return this.hashedPassword;
    }

    public void setPassword(String hashedPassword) {
        this.hashedPassword = hashedPassword;
    }

    public String getGroup() {
        return this.group;
    }

    public void setGroup(String group) {
        this.group = group;
    }    

}