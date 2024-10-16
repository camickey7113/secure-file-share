import java.util.*;

public class GroupList implements java.io.Serializable {
    public HashMap<String, Group> groups;

    public GroupList() {
        this.groups = new HashMap<String, Group>();
    }

    public synchronized boolean addGroup(Group group) {
        if(!groups.containsKey(group.getName())){
            groups.put(group.getName(), group);
            return true;
        }
        return false;
    }
    
    public synchronized boolean removeGroup(String groupName) {
        if(containsGroup(groupName)){
            groups.remove(groupName);
            return true;
        }
        return false;
    }

    public synchronized boolean containsGroup(String groupName) {
        return groups.containsKey(groupName);
    }

    public synchronized Group getGroup(String groupname) {
        return groups.get(groupname);
    }
}
