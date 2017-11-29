/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.IOException;
import java.security.*;
import javax.crypto.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;


/**
 *
 * @author gennaroavitabile
 */
public class KeychainTester {

    
        public static void main(String[] args) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, ClassNotFoundException, BadPaddingException {
        // TODO code application logic here
        
        
        Map<String, char[]> passwords= new HashMap<>();
        Map<String, String> filesChiaviPrivate= new HashMap<>();
        passwords.put("Caparezza", "prigioniero709".toCharArray());
        filesChiaviPrivate.put("Caparezza", "keyring/Caparezza.kc");
        passwords.put("Mikimix", "sanremo".toCharArray());
        filesChiaviPrivate.put("Mikimix", "keyring/Mikimix.kc");
        KeychainUtils.generateKeyPairs(passwords, "pubblici/chiaviPub.pub", filesChiaviPrivate);
        
        //Aggiunta di password
        System.out.println("-----Aggiunte di password---------");
        Map<String, String> passtoadd= new HashMap<>();
        passtoadd.put("Pass/Facebook/Michele", "puglia");
        passtoadd.put("Pass/Facebook/CaparezzaFanPage", "fanpage");
        passtoadd.put("Pass/Gmail/Booking", "live17");
        KeychainUtils.addPassInKeychain("keyring/Caparezza.kc", passtoadd, "prigioniero709".toCharArray());
        System.out.println("Pass/Facebook/Michele -> puglia");
        System.out.println("Pass/Facebook/CaparezzaFanPage -> fanpage");
        System.out.println("Pass/Gmail/Booking -> live17");
        
        //Aggiunta di una chiave RSA ulteriore
        System.out.println("-----Aggiunta di chiave-------");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = null;
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024,random);
        KeyPair RSAKeys1024 = keyPairGenerator.generateKeyPair();
        HashMap<String,PrivateKey> keyToAdd= new HashMap<>();
        keyToAdd.put("Key/RSA/1024/EtichettaDiscografica", RSAKeys1024.getPrivate());
        KeychainUtils.addKeysInKeychain("keyring/Caparezza.kc",keyToAdd, "prigioniero709".toCharArray());
        System.out.println("Chiave Key/RSA/1024/EtichettaDiscografica aggiunta correttamente");

        
        //Inizializzazione keyring
        Keychain keychainCapa=new Keychain("keyring/Caparezza.kc", "prigioniero709".toCharArray());
        
        
        //Prelievo di password
        System.out.println("---Prelievo di password----");
        System.out.println("Expected: puglia");
        System.out.println("Pass/Facebook/Michele ->"+ keychainCapa.getPassword("Pass/Facebook/Michele"));
        System.out.println("Expected: fanpage");
        System.out.println("Pass/Facebook/CaparezzaFanPage ->"+ keychainCapa.getPassword("Pass/Facebook/CaparezzaFanPage"));
        System.out.println("Expected: live17");
        System.out.println("Pass/Gmail/Booking ->"+ keychainCapa.getPassword("Pass/Gmail/Booking"));
  
        
        //Prelievo di chiave
        System.out.println("---Prelievo di chiave----");
        PrivateKey etichetta= keychainCapa.getPrivateKey("Key/RSA/1024/EtichettaDiscografica");
        System.out.println("Controllo di corretto prelievo expected true");  
        System.out.println(Base64.getEncoder().encodeToString(RSAKeys1024.getPrivate().getEncoded()).compareTo(Base64.getEncoder().encodeToString(etichetta.getEncoded()))==0);
        
        
        //Rimozioni di passord e chiave
        System.out.println("---Rimozione delle chiave e password aggiunte----");
        KeychainUtils.rmvInKeychain("keyring/Caparezza.kc",new LinkedList<String>(passtoadd.keySet()), "prigioniero709".toCharArray());
        KeychainUtils.rmvInKeychain("keyring/Caparezza.kc",new LinkedList<String>(keyToAdd.keySet()), "prigioniero709".toCharArray());

        keychainCapa=new Keychain("keyring/Caparezza.kc", "prigioniero709".toCharArray());
        
        System.out.println("---Prelievo di password----");
        System.out.println("Expected: null");
        System.out.println("Pass/Facebook/Michele ->"+ keychainCapa.getPassword("Pass/Facebook/Michele"));
        System.out.println("Expected: null");
        System.out.println("Pass/Facebook/CaparezzaFanPage ->"+ keychainCapa.getPassword("Pass/Facebook/CaparezzaFanPage"));
        System.out.println("Expected: null");
        System.out.println("Pass/Gmail/Booking ->"+ keychainCapa.getPassword("Pass/Gmail/Booking"));
        
        System.out.println("---Prelievo di chiave----");
        etichetta= keychainCapa.getPrivateKey("Key/RSA/1024/EtichettaDiscografica");
        
        System.out.println("Expected: chiave assente");  
        if(etichetta==null)
            System.out.println("Chiave assente");
        else
            System.out.println("Chiave prelevata: ->"+Base64.getEncoder().encodeToString(etichetta.getEncoded()));
  
    }
    
}
