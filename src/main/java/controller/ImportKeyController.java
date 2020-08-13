/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.bouncycastle.bcpg.ArmoredInputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 *
 * @author Korisnik
 */
public class ImportKeyController{

    public static void importKey()
    {
        File file = null;
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
	} catch (FileNotFoundException e) {
            // TODO Auto-generated catch block

	} catch (IOException | PGPException e) {
            // TODO Auto-generated catch block

	}
        // TODO Auto-generated catch block
        
    }
    
     @SuppressWarnings("rawtypes")
	  public static void readPublicKey(InputStream input) throws IOException, PGPException {

	    PGPPublicKeyRingCollection pgpPub =
	        new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new BcKeyFingerprintCalculator());

	    /*
	     we just loop through the collection till we find a key suitable for encryption, in the
	     real world you would probably want to be a bit smarter about this.
		 
		 Dakle cim se nadje kljuc pogodan za sifrovanje, uzimamo ga i iskacemo iz petlji.
		 Posto prilikom importa imamo jedan kljuc u asc fajlu ovo je ok nacin, jer ce naci taj jedan jedini.
	    */
            
            // keyRing is the key
	    Iterator keyRingIter = pgpPub.getKeyRings();
	    while (keyRingIter.hasNext()) {
	      PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();
              System.out.println("Zorana: " + keyRing.getPublicKey().getUserIDs().next());
	      
	    }
            
	 }
}
