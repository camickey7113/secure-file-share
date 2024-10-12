import java.util.*;

public class Group implements java.io.Serializable {
    String name;

    ArrayList<User> userList;

    public Group(String name) {
        this.name = name;
        this.userList = new ArrayList<User>();
    }

    public Group(String name, ArrayList<User> userList) {
        this.name = name;
        this.userList = userList;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public ArrayList<User> getUserList() {
        return this.userList;
    }

    public void setUserList(ArrayList<User> userList) {
        this.userList = userList;
    }
}