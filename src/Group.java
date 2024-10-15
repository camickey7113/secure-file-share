//import java.util.*;

public class Group implements java.io.Serializable {
    String name;

    UserList members;

    public Group(String name) {
        this.name = name;
        this.members = new UserList();
    }

    public Group(String name, UserList members) {
        this.name = name;
        this.members = members;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public UserList getMembers() {
        return this.members;
    }

    public void setMembers(UserList members) {
        this.members = members;
    }
    
    public boolean addMember(User member) {
        return members.addUser(member);
    }

    public boolean removeMember(User member) {
        return members.deleteUser(member.getUsername());
    }

    public boolean removeMember(String username) {
        return members.deleteUser(username);
    }

}