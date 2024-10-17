import java.io.File;

public class AutoSaveThread extends Thread {
    private final AuthServer server;
    private final File userFile;
    private final File groupFile;
    
    public AutoSaveThread(AuthServer server, File userFile, File groupFile) {
        this.server = server;
        this.userFile = userFile;
        this.groupFile = groupFile;
    }
    
    @Override
    public void run() {
        while (true) {
            try {
                // Save the user and group lists periodically (e.g., every 60 seconds)
                server.saveUserList(userFile);
                server.saveGroupList(groupFile);
                Thread.sleep(60000); // 60 seconds
            } catch (Exception e) {
                System.err.println("Error during auto-save: " + e.getMessage());
            }
        }
    }
}
    

