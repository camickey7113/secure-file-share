import java.lang.Thread;            
import java.net.Socket;
import java.io.ObjectInputStream;   
import java.io.ObjectOutputStream; 
import java.util.*;

public class AuthThread extends Thread
{
    private AuthServer server;
    private final Socket socket;

    public AuthThread(AuthServer server, Socket socket) {
        this.server = server;
        this.socket = socket;
    }

    public Token generateToken() {
        return null;
    }

    public boolean handleRootCommand(String command, Token token) {
        return false;
    }

    public void run() {

    } 

} 