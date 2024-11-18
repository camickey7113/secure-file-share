import java.util.*;


public class Message implements java.io.Serializable {
    private String command;
    private Token token;
    private byte[] signature;
    private ArrayList<Object> stuff;
    
    // Message Constructors
    // public Message(String cmd){
    //     this.command = cmd;
    //     stuff = new ArrayList<Object>();
    // }

    // public Message(ArrayList<Object> stuff){
    //     this.stuff = stuff;
    //     this.command = null;
    // }
    public Message(String cmd, Token token, ArrayList<Object> stuff){
        this.command = cmd;
        this.token = token;
        this.signature = null;
        this.stuff = stuff;
    }

    public Message(String cmd, Token token, byte[] signature, ArrayList<Object> stuff){
        this.command = cmd;
        this.token = token;
        this.signature = signature;
        this.stuff = stuff;
    }

    // Getters
    public String getCommand() {
        return command;
    }

    public Token getToken() {
        return token;
    }

    public ArrayList<Object> getStuff() {
        return stuff;
    }

    public byte[] getSignature() {
        return signature;
    }

    // Setters
    public void setCommand(String cmd) {
        this.command = cmd;
    }

    public void setToken(Token token) {
        this.token = token;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
    
    public boolean addStuff(Object item) {
        return stuff.add(item);
    }
    
    public boolean removeItem(Object item) {
        return stuff.remove(item);
    }
    
    public void removeAll() {
        stuff.clear();
    }

}