//import java.io.Serializable;


public class User implements java.io.Serializable {
    private String username;
    private String salt;
    private String hashedPassword;
    private String group; 

    public User(String username, String hashedPassword, String group, String salt) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        
        // set group to null if the user is root. 
        if (username.equals("root")){
            this.group = null; // root user, no group 
            //this.salt = 0;
        }
        else{
            this.group = group; //student 
            this.salt = salt;
        }

    }

    
    public String getUsername() {
        return this.username;
    }

    public String setSalt(String salt){
        return this.salt;
    }
    public String getSalt() { 
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