/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package controller;

import java.awt.SystemColor;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import model.ProjectMainModel;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 *
 * @author Korisnik
 */
public class KeysController 
{
    public static void initKeyRingsCollection()
    {
        initPublicKeyRingsCollection();
        initSecretKeyRingsCollection();
    }
    
    public static void initPublicKeyRingsCollection()
    {
        try 
        {
            InputStream input;
                input = new ArmoredInputStream(new FileInputStream(ProjectMainModel.pathPublicKeyFile));
            ProjectMainModel.publicKeyRingCollection =
                    new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new BcKeyFingerprintCalculator());
        } 
        catch (IOException | PGPException ex) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static void initSecretKeyRingsCollection()
    {
        try 
        {
            InputStream input;
                input = new ArmoredInputStream(new FileInputStream(ProjectMainModel.pathSecretKeyFile));
            ProjectMainModel.secretKeyRingCollection =
                    new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), new BcKeyFingerprintCalculator());
        } 
        catch (IOException | PGPException ex) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static void importPublicKey()
    {
        File file;
        JFileChooser fileChooser = new JFileChooser("Choose file to be imported. ");
	FileNameExtensionFilter filter = new FileNameExtensionFilter("KEY FILES", "asc");
	fileChooser.setFileFilter(filter);
	int retVal = fileChooser.showOpenDialog(null);
	
	try {
            if(retVal == JFileChooser.APPROVE_OPTION)
            {
		file = fileChooser.getSelectedFile();
		System.out.println(file.getName());
                readPublicKey(new ArmoredInputStream(new FileInputStream(file)));
            }
	} 
        catch (FileNotFoundException e) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, e);
	} 
        catch (IOException ex) { 
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }
    
    public static void importSecretKey()
    {
        File file;
        JFileChooser fileChooser = new JFileChooser("Choose file to be imported. ");
	FileNameExtensionFilter filter = new FileNameExtensionFilter("KEY FILES", "asc");
	fileChooser.setFileFilter(filter);
	int retVal = fileChooser.showOpenDialog(null);
	
	try {
            if(retVal == JFileChooser.APPROVE_OPTION)
            {
		file = fileChooser.getSelectedFile();
		System.out.println(file.getName());
                readSecretKey(new ArmoredInputStream(new FileInputStream(file)));
            }
	} 
        catch (FileNotFoundException ex) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        } 
        catch (IOException ex) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    @SuppressWarnings("rawtypes")
    public static void readPublicKey(InputStream input)
    {
        PGPPublicKeyRingCollection tempPublicKeyRingCollection;
        try {
            tempPublicKeyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new BcKeyFingerprintCalculator());
            Iterator keyRingIter = tempPublicKeyRingCollection.getKeyRings();
            if(ProjectMainModel.publicKeyRingCollection == null)
                ProjectMainModel.publicKeyRingCollection = tempPublicKeyRingCollection;
            else 
            {
                while (keyRingIter.hasNext()) 
                {
                    PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();
                    System.out.println("Zorana public: " + keyRing.getPublicKey().getUserIDs().next());
                    if(!ProjectMainModel.publicKeyRingCollection.contains(keyRing.getPublicKey().getKeyID()))
                        ProjectMainModel.publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(ProjectMainModel.publicKeyRingCollection, keyRing);
                }
            }
        } 
        catch (IOException | PGPException ex) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    
    @SuppressWarnings("rawtypes")
    public static void readSecretKey(InputStream input)
    {
        PGPSecretKeyRingCollection tempSecretKeyRingCollection;
        try 
        {
            tempSecretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), new BcKeyFingerprintCalculator());
            Iterator keyRingIter = tempSecretKeyRingCollection.getKeyRings();
            if(ProjectMainModel.secretKeyRingCollection == null)
                ProjectMainModel.secretKeyRingCollection = tempSecretKeyRingCollection;
            else 
            {
                while (keyRingIter.hasNext()) 
                {
                    PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
                    System.out.println("Zorana secret: " + keyRing.getSecretKey().getUserIDs().next());
                    if(!ProjectMainModel.secretKeyRingCollection.contains(keyRing.getSecretKey().getKeyID()))
                        ProjectMainModel.secretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(ProjectMainModel.secretKeyRingCollection, keyRing);
                }
            }
        }
        catch (IOException | PGPException ex) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }
    
    public static void exportAllPublicKeys()
    {    
        ArmoredOutputStream outputFile;
        try {
            outputFile = new ArmoredOutputStream(new FileOutputStream(ProjectMainModel.pathPublicKeyFile));
            Iterator keyRingIter = ProjectMainModel.publicKeyRingCollection.getKeyRings();
            {
                while (keyRingIter.hasNext()) 
                {
                    PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();
                    System.out.println("Export public: " + keyRing.getPublicKey().getUserIDs().next());
                    keyRing.encode(outputFile);
                }
            }
            outputFile.close();
        } 
        catch (FileNotFoundException ex) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        } 
        catch (IOException ex) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    public static void exportAllSecretKeys()
    {    
        ArmoredOutputStream outputFile;
        try {
            outputFile = new ArmoredOutputStream(new FileOutputStream(ProjectMainModel.pathSecretKeyFile));
            Iterator keyRingIter = ProjectMainModel.secretKeyRingCollection.getKeyRings();
            {
                while (keyRingIter.hasNext()) 
                {
                    PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
                    System.out.println("Export secret: " + keyRing.getSecretKey().getUserIDs().next());
                    keyRing.encode(outputFile);
                }
            }
            outputFile.close();
        } 
        catch (FileNotFoundException ex) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        } 
        catch (IOException ex) 
        {
            Logger.getLogger(KeysController.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
}

