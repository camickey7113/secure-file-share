import java.util.*;

public class GroupList implements java.io.Serializable {
    private HashMap<String, Group> groups;

    public GroupList() {
        this.groups = new HashMap<String, Group>();
    }

    public boolean addGroup(Group group) {
        if(!groups.containsKey(group.getName())){
            groups.put(group.getName(), group);
            return true;
        }
        return false;
    }
    
    public boolean removeGroup(String groupName) {
        if(containsGroup(groupName)){
            groups.remove(groupName);
            return true;
        }
        return false;
    }

    public boolean containsGroup(String groupName) {
        return groups.containsKey(groupName);
    }

    public Group getGroup(String groupname) {
        return groups.get(groupname);
    }
}
