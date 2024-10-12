import java.util.*;

public class UserList implements java.io.Serializable {

    private HashMap<String, User> list = new HashMap<String, User>();

    public synchronized boolean addUser(User user){
        return false;
    }

    public synchronized boolean deleteUser(String userName){
        return false;
    }


}