public class Token {
    public String username;
    public String password;
    public String group; // only applies to student users



    public Token(String username, String password, String group) {
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

}
