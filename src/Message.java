import java.util.*;


public class Message implements java.io.Serializable {
    private String command;
    private ArrayList<Object> stuff;
    
    // Message Constructors
    public Message(String cmd){
        command = cmd;
        stuff = new ArrayList<Object>();
    }
    public Message(ArrayList<Object> stuff){
        this.stuff = stuff;
        command = null;
    }
    public Message(String cmd, ArrayList<Object> stuff){
        command = cmd;
        this.stuff = stuff;
    }

    // Getters
    public String getCommand(){
        return command;
    }
    public ArrayList<Object> getStuff(){
        return stuff;
    }

    //Setters
    public boolean setCommand(String cmd){
        command = cmd;
        return false;
    }
    
    public boolean addStuff(Object item){
        return stuff.add(item);
    }
    
    public boolean removeItem(Object item){
        return stuff.remove(item);
    }
    
    public void removeAll(){
        stuff.clear();
    }

}