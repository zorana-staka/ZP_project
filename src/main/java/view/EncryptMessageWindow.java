/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package view;

import controller.EncryptionController;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import model.ProjectMainModel;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 *
 * @author Korisnik
 */
public class EncryptMessageWindow extends javax.swing.JFrame {

    /**
     * Creates new form EncryptMessageWindow
     */
    public EncryptMessageWindow() {
        initComponents();
        populateComboBoxes();
    }

    private void populateComboBoxes()
    {        
        Iterator keyRingIter =  ProjectMainModel.publicKeyRingCollection.getKeyRings();
        while (keyRingIter.hasNext()) 
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();
            System.out.println("Cb public: " + keyRing.getPublicKey().getUserIDs().next());
            getCbPublicKeys().addItem(
                    keyRing.getPublicKey().getUserIDs().next() + 
                            " ( " +  keyRing.getPublicKey().getCreationTime() + " )");            
        }
        
        keyRingIter =  ProjectMainModel.secretKeyRingCollection.getKeyRings();
        while (keyRingIter.hasNext()) 
        {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
            System.out.println("Cb secret: " + keyRing.getPublicKey().getUserIDs().next());
            getCbSecretKeys().addItem(
                    keyRing.getSecretKey().getUserIDs().next() + 
                            " (  )");            
        }
    }
    
    private Boolean checkPass()
    {
        String secretKeyUserId = (cbSecretKeys.getSelectedItem().toString().split("\\(")[0]).strip();
        System.out.println("User id: " + secretKeyUserId);
        PGPSecretKey secretKey = null;
        Iterator secretKeyRingIter =  ProjectMainModel.secretKeyRingCollection.getKeyRings();
        while (secretKeyRingIter.hasNext()) 
        {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) secretKeyRingIter.next();
            if(keyRing.getSecretKey().getUserIDs().next().toString().equals(secretKeyUserId))                        
                  secretKey = keyRing.getSecretKey();
        }        
        if(secretKey != null)
            System.out.println("Secret key: " + Long.toHexString(secretKey.getKeyID()));  
                    
        char[] password = passField.getPassword();
        PGPPrivateKey pgpPrivKey = null;
        try {
            pgpPrivKey = secretKey.extractPrivateKey
            (new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password));
        } catch (PGPException ex) {
            Logger.getLogger(EncryptionController.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        if(pgpPrivKey == null)
            return false;
        return true;
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        cbSign = new javax.swing.JCheckBox();
        cbEncrypt = new javax.swing.JCheckBox();
        cbSecretKeys = new javax.swing.JComboBox<>();
        cbPublicKeys = new javax.swing.JComboBox<>();
        btnCancel = new javax.swing.JButton();
        btnOk = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        passField = new javax.swing.JPasswordField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        cbSign.setText("Sign as:");

        cbEncrypt.setText("Encrypt for: ");

        btnCancel.setText("Cancel");

        btnOk.setText("Sign / Encrypt");

        jLabel1.setText("Please enter the passphrase to unlock the OpenPGP secret key");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(btnOk)
                        .addGap(169, 169, 169)
                        .addComponent(btnCancel, javax.swing.GroupLayout.PREFERRED_SIZE, 82, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(cbEncrypt, javax.swing.GroupLayout.DEFAULT_SIZE, 103, Short.MAX_VALUE)
                            .addComponent(cbSign, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(cbPublicKeys, 0, 405, Short.MAX_VALUE)
                            .addComponent(cbSecretKeys, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 297, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(passField, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(119, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(58, 58, 58)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(cbSign)
                    .addComponent(cbSecretKeys, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(62, 62, 62)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(cbEncrypt)
                    .addComponent(cbPublicKeys, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(26, 26, 26)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(passField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 139, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnCancel)
                    .addComponent(btnOk))
                .addGap(47, 47, 47))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

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
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(EncryptMessageWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(EncryptMessageWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(EncryptMessageWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(EncryptMessageWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new EncryptMessageWindow().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnCancel;
    private javax.swing.JButton btnOk;
    private javax.swing.JCheckBox cbEncrypt;
    private javax.swing.JComboBox<String> cbPublicKeys;
    private javax.swing.JComboBox<String> cbSecretKeys;
    private javax.swing.JCheckBox cbSign;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JPasswordField passField;
    // End of variables declaration//GEN-END:variables

    /**
     * @return the cbPublicKeys
     */
    public javax.swing.JComboBox<String> getCbPublicKeys() {
        return cbPublicKeys;
    }

    /**
     * @return the cbSecretKeys
     */
    public javax.swing.JComboBox<String> getCbSecretKeys() {
        return cbSecretKeys;
    }

    /**
     * @return the passField
     */
    public javax.swing.JPasswordField getPassField() {
        return passField;
    }
}
