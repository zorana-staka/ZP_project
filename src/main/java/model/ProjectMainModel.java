/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package model;

import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

/**
 *
 * @author Korisnik
 */
public class ProjectMainModel 
{
    public static PGPKeyRingGenerator keyRingGen;
    public static String pathPublicKeyFile = "C:\\Users\\Korisnik\\Desktop\\zorana_public.asc";;
    public static String pathSecretKeyFile = "C:\\Users\\Korisnik\\Desktop\\zorana_SECRET.asc";
    
    public static PGPPublicKeyRingCollection publicKeyRingCollection; 
    public static PGPSecretKeyRingCollection secretKeyRingCollection; 
}
