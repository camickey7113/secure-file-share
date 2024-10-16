import java.util.*;

public class UserList implements java.io.Serializable {

    // make this private warning
    private HashMap<String, User> userMap = new HashMap<String, User>();

    public synchronized boolean addUser(User user) {
        if (userMap.containsKey(user.getUsername())) {
            return false;
        } else {
            userMap.put(user.getUsername(), user);
        }
        return true;
    }

    public synchronized boolean deleteUser(String username) {
        if (!userMap.containsKey(username)){
            return false;
        } else {
            userMap.remove(username);
        }
        return true;
    }

    public synchronized boolean containsUser(String username) {
        return userMap.containsKey(username);
    }

    public synchronized User getUser(String username) {
        return userMap.get(username);
    }

    public synchronized HashMap<String, User> getUserMap(){
        return userMap;
    }
}