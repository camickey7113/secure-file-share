import java.io.ObjectInputStream; // We will extend Java's base Thread class
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList; // For reading Java objects off of the wire

/**
 * A simple server thread. This class just echoes the messages sent
 * over the socket until the socket is closed.
 *
 * @author Adam J. Lee (adamlee@cs.pitt.edu)
 */
public class EchoAuthThread extends Thread {
	private final Socket socket; // The socket that we'll be talking over
	private final ArrayList<User> userList;

	/**
	 * Constructor that sets up the socket we'll chat over
	 *
	 * @param _socket The socket passed in from the server
	 *
	 */
	public EchoAuthThread(Socket socket, ArrayList<User> userList) {
		this.socket = socket;
		this.userList = userList;
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


			Token token = null;
			// AUTHENTICATE LOOP
			while (token == null){

				// retrieve user object from the client

				User authAttempt = retrieveLogin(input);


				// got the user and pass. call authenticate on it.
				if (authenticate(authAttempt, userList)){ // if we were able to authenticate, give them a token
					token = generateToken(authAttempt.username, authAttempt.password, authAttempt.group);
					output.writeObject(new Message("Authentication successful", token));  // send token back to client
				}
				else {
					output.writeObject(new Message("Authentication failed, try again"));  // Failed authentication response
            	}

			}


			// proceed to regular message handling after user logs in
			Message msg = null;
			int count = 0;
			do {
				// read and print message
				msg = (Message) input.readObject();
				System.out.println("[" + socket.getInetAddress() + ":" + socket.getPort() + "] " + msg.theMessage);

				// Write an ACK back to the sender
				count++;
				output.writeObject(new Message("Message received: " + msg.theMessage));
				// in the future, we will 

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



	//helper methods --------------------------------------------------------------------------------------------------------------------------------------
	

	//generates a "token" based on the user's information
	private Token generateToken(String username, String password, String group) {
		if (username.equals("root")) {
			return new Token(username, password, null); // root user, no group
		} else {
			return new Token(username, password, group); // student with group
		}
	}

	private boolean authenticate(User possUser, ArrayList<User> userList){
		return userList.contains(possUser);
	}

	private User retrieveLogin(ObjectInputStream input){
		try{
			User authAttempt = (User)input.readObject();
			System.out.println("Received username: " + authAttempt.username);
        	System.out.println("Received password: " + authAttempt.password);
			return authAttempt;
		} catch (Exception e) {
			System.err.println("Error retrieving login information");
		}
		return null;
	}



	private boolean createUser(String username, String password, String group) { // will be for the root's purpose of creating ppl

		/* 
		 * When we actually add the user to the userlist, we need to:
		 * 	lock access to the file to synchronize 
		 * 	update our local copy of the list in the thread
		 * 	check for users that have that username
		 * 	update the file
		 * 	unlock the file
		 * 
		 * If we dont do this in this order, then race conditions :(
		 * The alternative is that every time we edit the file, 
		 * we manually insert the user in order, which seems like 
		 * a total pain in the ass. It should be way easier to just
		 * synchronize and overwrite the whole thing every time, even with
		 * hundreds of users (I think)
		 * 
		 */
		// make sure a username doesnt already exist
		for (User user : userList){
			if (user.username.equals(username)){
				System.out.println(username + " already exists.");
				return false;
			}
		}

		//add it if it doesn't
        User newUser =  new User(username, password, group);
		userList.add(newUser);
		return true;

    }

} // -- end class EchoAuthThread