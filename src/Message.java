/**
 * Very stupid-simple message class. By implementing the Serializble
 * interface, objects of this class can be serialized automatically by
 * Java to be sent across IO streams.
 *
 * @author Adam J. Lee (adamlee@cs.pitt.edu)
 *
 */


import java.io.Serializable;

public class Message implements Serializable {
    /** The text string encoded in this Message object */
    public String theMessage;

    public Token token;

    /**
     * Constructor.
     *
     * @param _msg The string to be encoded in this Message object
     *
     */
    public Message(String _msg) {
        theMessage = _msg;
    }

    public Message(String _msg, Token _token) {
        theMessage = _msg;
        token = _token;
    }


} // -- End class Message