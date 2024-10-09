import java.net.ServerSocket;  // The server uses this to bind to a port
import java.net.Socket;        // Incoming connections are represented as sockets
import java.util.Scanner;

/**
 * A simple server class.  Accepts client connections and forks
 * EchoThreads to handle the bulk of the work.
 *
 * @author Adam J. Lee (adamlee@cs.pitt.edu)
 *
 */
public class EchoAuthServer
{
	
    /** The server will listen on this port for client connections */
    public static int SERVER_PORT = 0;

    /**
     * Main routine.  Just a dumb loop that keeps accepting new
     * client connections.
     *
     */
    public static void main(String[] args)
    {
		Scanner scanner = new Scanner(System.in);
	try{
		System.out.println("Specify which port you want to bind to: ");
		SERVER_PORT = scanner.nextInt();
		
	    // This is basically just listens for new client connections
	    final ServerSocket serverSock = new ServerSocket(SERVER_PORT);
	    
	    // A simple infinite loop to accept connections
	    Socket sock = null;
	    EchoThread thread = null;
	    while(true){
			sock = serverSock.accept();     // Accept an incoming connection
			thread = new EchoThread(sock);  // Create a thread to handle this connection
			thread.start();                 // Fork the thread
	    }                                   // Loop to work on new connections while this
                                                // the accept()ed connection is handled

	}
	catch(Exception e){
	    System.err.println("Error: " + e.getMessage());
	    e.printStackTrace(System.err);
	}

    }  //-- end main(String[])

} //-- End class EchoServer