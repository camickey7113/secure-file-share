import java.util.*;

public class GroupList implements java.io.Serializable {
    HashMap<String, Group> groups;

    public GroupList() {
        this.groups = new HashMap<String, Group>();
    }

    public boolean addGroup(Group group) {
        return false;
    }
    
    public boolean removeGroup(String groupName) {
        return false;
    }
}