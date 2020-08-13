import java.security.NoSuchAlgorithmException;

import controller.NewKeyPairGenController;
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
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
		MainWindow mainWindow = new MainWindow();
		//KeyPairGenController kpg = new KeyPairGenController();
		//kpg.GenerateKeyPair(4096);
		mainWindow.setVisible(true);
		String naziv = "Zoka je sve";
	}
		
}

