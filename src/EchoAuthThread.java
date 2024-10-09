import java.lang.Thread; // We will extend Java's base Thread class
import java.net.Socket;
import java.util.ArrayList;
import java.io.ObjectInputStream; // For reading Java objects off of the wire
import java.io.ObjectOutputStream; // For writing Java objects to the wire

/**
 * A simple server thread. This class just echoes the messages sent
 * over the socket until the socket is closed.
 *
 * @author Adam J. Lee (adamlee@cs.pitt.edu)
 */
public class EchoAuthThread extends Thread {
	private final Socket socket; // The socket that we'll be talking over
	// private String token;
	private Token token;

	private final ArrayList<User> userList;

	/**
	 * Constructor that sets up the socket we'll chat over
	 *
	 * @param _socket The socket passed in from the server
	 *
	 */
	public EchoAuthThread(Socket _socket, ArrayList<User> _userList) {
		socket = _socket;
		// token = "Bello";
		userList = _userList;
	}

	/**
	 * run() is basically the main method of a thread. This thread
	 * simply reads Message objects off of the socket.
	 *
	 */
	public void run() {
		try {
			// Print incoming message
			System.out.println("** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " **");

			// set up I/O streams with the client
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());


			// authenticate the client credentials
			// would call authenticate function here 
			// authenticate would check if the user name and password pair match in the data base?
			// would call generateToken function here


			// AUTHENTICATE LOOP
			while (token == null){
				Credentials information = (Credentials)input.readObject(); // reads info from client input stream and casts as message obj
				String username = information.username;
				String password = information.password; 
				// got the user and pass. call authenticate on it.
				if (authenticate(username, password)){ // if we were able to authenticate, give them a token
					token = generateToken(username, password);
				}

			}


			// Loop to read messages
			Message msg = null;
			int count = 0;
			do {
				// read and print message
				msg = (Message) input.readObject();
				System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.theMessage);

				// Write an ACK back to the sender
				count++;
				output.writeObject(new Message("Success", token)); // uncomment token bello and private string token to run how it used to 
				// when we generate a token, this will work

			} while (!msg.theMessage.toUpperCase().equals("EXIT"));

			// Close and cleanup
			System.out
					.println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
			socket.close();

		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	} // -- end run()


	
	private Token generateToken(String username, String password) {
		if (username.equals("root")) {
			return new Token(username, password, null); // root user, no group
		} else {
			String group = "group1"; // i just hard coded for now, will have to fix later
			return new Token(username, password, group); // student with group
		}
	}

	private boolean authenticate(String username, String password){
		for (User user: userList){
			if (user.username.equals(username) && user.password.equals(password)){
				return true;
			}
		}
		return false;
	}




	private User createUser(String username, String password) { // will be for the root's purpose of creating ppl

		// make sure a username doesnt already exist
		for (User user : userList){
			if (user.username.equals(username)){
				System.out.println(username + " already exists.");
				return null;
			}
		}

        return new User(username, password);
    }

} // -- end class EchoThread