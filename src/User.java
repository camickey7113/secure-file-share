import java.io.Serializable;

public class User implements Serializable{
    public String username;
    public String password;
    public String group;


    public User(String username, String password, String group){
        this.username = username;
        this.password = password;
        this.group = group;
    }
    

    //only comparing username and password because the equals is used in authentication, and users do not need to say which group they belong to during that process
    public boolean equals(User other){
        return (username.equals(other.username)) && (password.equals(other.password));
    }

}
