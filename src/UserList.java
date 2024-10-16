import java.util.*;

public class UserList implements java.io.Serializable {

    private static HashMap<String, User> userMap = new HashMap<String, User>();

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

    public synchronized static boolean containsUser(String username) {
        return userMap.containsKey(username);
    }

    public synchronized static User getUser(String username) {
        return userMap.get(username);
    }
}