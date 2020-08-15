import controller.EncryptionController;
import controller.KeysController;
import java.security.NoSuchAlgorithmException;

import java.io.IOException;
import view.MainWindow;

public class Main 
{
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException 
	{
            try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
            } 
            catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
                java.util.logging.Logger.getLogger(MainWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
            }
            
            
            KeysController.initKeyRingsCollection();
            MainWindow mainWindow = new MainWindow();
            //kpg.GenerateKeyPair(4096);
            mainWindow.setVisible(true);
            String naziv = "Zoka je slatko";

	}
		
}

