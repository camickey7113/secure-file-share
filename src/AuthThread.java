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

    public Token generateToken(User user) {
        Token newToken = new Token(user.getUsername(), user.getGroup());
    
        return newToken;
        //
    }

    public boolean handleRootCommand(String command, Token token) {
        return false;
    }
    
    public boolean authenticate(String username){
        // take a look at the user name and see if it exists
        // find out which user has that username
        // check that users group and see if the group exists
        if(UserList.containsUser(username)){
            System.out.println("User exists");
            User currentUser = UserList.getUser(username);
            if(GroupList.containsGroup(currentUser.getGroup()))
            {
                return true;
            }
            //find which group they are in
        
        }
        else{
            System.out.println("User and/or Group do not exist");
            return false;
        }
        return false;
       
    }
    

    public void run()
    {
        try {
            // Print incoming message
            System.out.println("** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " **");

            // set up I/O streams with the client
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

            // Loop to read messages
            User authUser = null;
            
            
            Message msg = null;
            //int count = 0;
            do {
           
            // read and print message
            msg = (Message)input.readObject();
            System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.getCommand());
            
            //find out who is the current user
            if(msg.getCommand().equals("login")){
                String authUsername = (String) msg.getStuff().get(0); //<--- THIS IS WHATS FAILING
               //authenticate the user
                if(authenticate(authUsername))
                    {
                    authUser = UserList.getUser(authUsername);
                    //get user from the username in the msg
                    Token t=generateToken(authUser);
                    //send message with token back to client:
                    Message returnMessage = new Message(msg.getCommand(), t, msg.getStuff());
                    output.writeObject(returnMessage);
                    //WRITE THIS ^
                
                    }

            }
            
   
            
            
            
            
            

            } while(!msg.getCommand().toUpperCase().equals("EXIT"));

            // Close and cleanup
            System.out.println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
            socket.close();

        }
        catch(Exception e){
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

} 