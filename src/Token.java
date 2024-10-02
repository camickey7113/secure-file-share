public class Token {
    public String username;
    public String password;
    public boolean writeCreateOrDeleteFile; // true if you are a student and in your group folder. or, simply if you are root.
    public boolean manageUsers; // create or delete users. only true if you are root.
    public String group; // only applies to student users



    public Token(String username, String password, boolean writeCreateOrDeleteFile, boolean manageUsers, String group) {
        this.username = username;
        this.password = password;
        this.writeCreateOrDeleteFile = writeCreateOrDeleteFile;
        this.manageUsers = manageUsers;


        // set group to null if the user is root. 
        if (username.equals("root")){
            this.group = null; // root user, no group 
        }
        else{
            this.group = group; //student 
        }

    }

}
