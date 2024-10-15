//import java.io.Serializable;


public class User implements java.io.Serializable {
    private String username;
    private String password;
    private String group; 

    public User(String username, String password, String group) {
        this.username = username;
        this.password = password;
        // set group to null if the user is root. 
        if (username.equals("root")){
            this.group = null; // root user, no group 
        }
        else{
            this.group = group; //student 
        }

    }

    
    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getGroup() {
        return this.group;
    }

    public void setGroup(String group) {
        this.group = group;
    }    

}