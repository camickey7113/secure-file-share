public class Token {
    public String username;
    public String password;
    public boolean userType; // either student or root. if you are a student, you can write, create, or delete a file that is 
    boolean read;
    boolean ableToCreateUser_or_ableToDeleteUser;
}

