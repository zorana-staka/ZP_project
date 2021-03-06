/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package view;

import controller.EncryptionController;
import controller.KeysController;
import controller.NewKeyPairGenController;
import java.io.IOException;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.DefaultTableModel;
import model.ProjectMainModel;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

/**
 *
 * @author Korisnik
 */
public class MainWindow extends javax.swing.JFrame {

    /**
     * Creates new form MainWindow
     * @throws java.io.IOException
     */
    
    public MainWindow() throws IOException {
        initComponents();
        populateTable();
        menuItemNewKeyPair.addActionListener(new NewKeyPairGenController(this));
        menuItemEncryptFiles.addActionListener(new EncryptionController());
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jMenuItem1 = new javax.swing.JMenuItem();
        jToolBar1 = new javax.swing.JToolBar();
        jScrollPane1 = new javax.swing.JScrollPane();
        keyTable = new javax.swing.JTable();
        jMenuBar1 = new javax.swing.JMenuBar();
        menuFile = new javax.swing.JMenu();
        menuItemNewKeyPair = new javax.swing.JMenuItem();
        menuItemImportSecretKey = new javax.swing.JMenuItem();
        menuItemImportPublicKey = new javax.swing.JMenuItem();
        menuItemEncryptFiles = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();

        jMenuItem1.setText("jMenuItem1");

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                formWindowClosing(evt);
            }
        });

        jToolBar1.setRollover(true);

        keyTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null}
            },
            new String [] {
                "Name", "E-mail", "Valid From", "Valid Until", "Key-ID"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jScrollPane1.setViewportView(keyTable);

        menuFile.setText("File");

        menuItemNewKeyPair.setText("New Key Pair");
        menuItemNewKeyPair.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                menuItemNewKeyPairMouseClicked(evt);
            }
        });
        menuFile.add(menuItemNewKeyPair);

        menuItemImportSecretKey.setText("Import Secret Key");
        menuItemImportSecretKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                menuItemImportSecretKeyActionPerformed(evt);
            }
        });
        menuFile.add(menuItemImportSecretKey);

        menuItemImportPublicKey.setText("Import Public Key");
        menuItemImportPublicKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                menuItemImportPublicKeyActionPerformed(evt);
            }
        });
        menuFile.add(menuItemImportPublicKey);

        menuItemEncryptFiles.setText("Encrypt File");
        menuFile.add(menuItemEncryptFiles);

        jMenuBar1.add(menuFile);

        jMenu2.setText("Edit");
        jMenuBar1.add(jMenu2);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jToolBar1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 591, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jToolBar1, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 132, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 93, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void menuItemNewKeyPairMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_menuItemNewKeyPairMouseClicked
        populateTable();
    }//GEN-LAST:event_menuItemNewKeyPairMouseClicked

    private void menuItemImportPublicKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_menuItemImportPublicKeyActionPerformed
        KeysController.importPublicKey();
        populateTable();
    }//GEN-LAST:event_menuItemImportPublicKeyActionPerformed

    private void menuItemImportSecretKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_menuItemImportSecretKeyActionPerformed
        KeysController.importSecretKey();
        populateTable();
    }//GEN-LAST:event_menuItemImportSecretKeyActionPerformed

    private void formWindowClosing(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowClosing
        KeysController.exportAllPublicKeys();
        KeysController.exportAllSecretKeys();
    }//GEN-LAST:event_formWindowClosing

    public void populateTable()
    {
        DefaultTableModel model = new DefaultTableModel(new String[] {"Name", "E-mail", "Valid From", "Valid Until", "Key ID"}, 0);
        
        Iterator keyRingIter =  ProjectMainModel.publicKeyRingCollection.getKeyRings();
        while (keyRingIter.hasNext()) 
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();
            System.out.println("Zorana public: " + keyRing.getPublicKey().getUserIDs().next());
            model.addRow(new Object[] 
                { 
                    extractNameFromKeyId(keyRing.getPublicKey().getUserIDs().next().toString()), 
                    extractEmailFromKeyId(keyRing.getPublicKey().getUserIDs().next().toString()), 
                    keyRing.getPublicKey().getCreationTime(), 
                    keyRing.getPublicKey().getValidSeconds(), 
                    Long.toHexString(keyRing.getPublicKey().getKeyID())
                });            
        }
        
        keyRingIter =  ProjectMainModel.secretKeyRingCollection.getKeyRings();
        while (keyRingIter.hasNext()) 
        {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
            System.out.println("Zorana private: " + keyRing.getSecretKey().getUserIDs().next());
            model.addRow(new Object[] 
            {
                extractNameFromKeyId(keyRing.getSecretKey().getUserIDs().next().toString()), 
                extractEmailFromKeyId(keyRing.getSecretKey().getUserIDs().next().toString()), 
                0, 
                0, 
                Long.toHexString(keyRing.getSecretKey().getKeyID())
            });            
        }
        
        keyTable.setModel(model);
    }
    
    private String extractNameFromKeyId(String keyId)
    {
        return (keyId.split("<")[0]).strip();
    }
    
    private String extractEmailFromKeyId(String keyId)
    {
        return (keyId.split("<")[1]).split(">")[0];
    }
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
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
        //</editor-fold>
        
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    new MainWindow().setVisible(true);
                } catch (IOException ex) {
                    Logger.getLogger(MainWindow.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JToolBar jToolBar1;
    private javax.swing.JTable keyTable;
    private javax.swing.JMenu menuFile;
    private javax.swing.JMenuItem menuItemEncryptFiles;
    private javax.swing.JMenuItem menuItemImportPublicKey;
    private javax.swing.JMenuItem menuItemImportSecretKey;
    private javax.swing.JMenuItem menuItemNewKeyPair;
    // End of variables declaration//GEN-END:variables
}
