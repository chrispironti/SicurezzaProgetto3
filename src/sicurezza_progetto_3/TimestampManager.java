/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.util.*;
import org.json.JSONObject;


/**
 * Il compito di questa classe è generare le richieste di Timestamp da inoltrare
 * al server TSA, ricevere i messaggi corrispondenti e verificarne la validità.
 * Viene generato l'hash associato al messaggio dell'utente i, si allega il suo ID,
 * viene firmato il tutto e poi cifrato.
 * Il server TSA genera il timestamp, lo firma e cifra la risposta. Una volta ricevuta viene valutata
 * la validità della firma apposta dal TSA, vengono usate le informazioni contenute
 * nel timestamp per controllare HV e SHV con il proprio hash, e infine viene firmato
 * il timestamp stesso, in maniera tale da proteggersi nel caso di scadenza di esso.
 * 
 * Supponiamo che in ogni timeframe inviamo al server una Map di richieste che deve gestire
 * tutte. Ogni elemento della Map è una stringa cifrata di un JSONObject contenente:
 * 1)IDUtente
 * 2)Hash del messaggio
 * 2)Algoritmo di firma
 * 3)Firma 
 * Lui ci risponde con una Map di risposte di cui dobbiamo verificare la validità.
 */

public class TimestampManager {
    
    private int requestsNumber; //Numero di richieste nel Time Frame i
    private int IDNumber; //Inizializzato a 0, lo incrementiamo per ogni utente che fa le richieste
    private TSA TSAServer; //TSA Server
    private ArrayList<TSAMessage> requests;
    private ArrayList<TSAMessage> responses;
    private ArrayList<String> nomiFiles;
    
    public TimestampManager(TSA TSAServer){
        this.TSAServer = TSAServer;
        this.requestsNumber = 0;
        this.IDNumber = 0;
        this.requests = null;
        this.responses = null;
    }
    

    /*Il metodo riceve un oggetto utente e il messaggio a cui vuole apporre la 
    marca temporale. Il metodo genera l'hash di message e passa l'hash e 
    l'oggetto User al costruttore di TSARequest. 
    In TSARequest vengono inseriti in un JSONObject il quale viene firmato e cifrato. 
    La TSARequest viene poi inserita nella map come chiave l'id dell'utente e come
    valore l'oggetto TSARequest. Se un utente richiede più di una marca, le TSARequest
    vengono salvate in un array. Se il numero di richieste ha raggiunto il numero
    massimo consentito (8) chiama sendRequests.
    */
    public void generateRequest(String keychainFile, String userID, char[] password, String documentFile) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException, UnsupportedEncodingException, SignatureException, NotVerifiedSignException{
        requestsNumber += 1;
        
        //Ottengo la chiave privata Dsa dell'user dal keyring
        Keychain userKeyChain = new Keychain(keychainFile, password);
        PrivateKey dsaPrivKeyUser = userKeyChain.getPrivateKey("Key/DSA/2048/Main");
        //Ottengo la chiave pubblica Rsa della TSA dal file di chiavi pubbliche
        PublicKey rsaPubKeyTsa = PublicKeysManager.getPublicKeysManager().getPublicKey("TSA", "Key/RSA/2048/Main");
        //Calcolo digest del messaggio
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Algoritmo non supportato");
        }
        BufferedInputStream is = new BufferedInputStream(new FileInputStream(documentFile));
        DigestInputStream dis = new DigestInputStream(is, md);
        while (dis.read() != -1)
            ;
        byte[] msgDigest = md.digest();
        
        //Creo il Json con User Id e msgDigest
        JSONObject j = new JSONObject();
        j.put("userID", userID);
        j.put("msgDigest", Base64.getEncoder().encodeToString(msgDigest));
        
        //Crea la richiesta
        TSAMessage req = new TSAMessage(j, dsaPrivKeyUser, rsaPubKeyTsa);
        
        //Aggiunge la richiesta all'ArrayList
        if(requests==null){
            requests = new ArrayList<>();   
        }
        requests.add(req);

        if (requestsNumber == 8){
            this.processRequests();
        }
    }
    
    /*Manda la map di richieste al server TSA e salva le risposte nella mappa
    corrispondente della classe. Può essere chiamato in un qualunque momento dall'utente
    o automaticamente da generateRequest quando il numero max di richieste è stato raggiunto.
    */
    public void processRequests() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException, UnsupportedEncodingException, SignatureException, NotVerifiedSignException{ 
        responses=TSAServer.generateTimestamp(requests);      
        //chiama un metodo che verifica, decifra e salva rispos
        processResponses();
        this.requestsNumber = 0;
        this.requests = new ArrayList<>();
    }

    /*
    Lancia un'eccezione per l utente i-esimo se 
    la sua marca non è verificata*/ 
    /*Attenzione usa lista nomi file per salvarli*/
    public void processResponses() throws UnsupportedEncodingException, IOException, InvalidKeyException, SignatureException, NotVerifiedSignException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        PublicKey dsaPubKeyTsa = PublicKeysManager.getPublicKeysManager().getPublicKey("TSA", "Key/DSA/2048/Main");
        for (TSAMessage r: this.responses){
            //Verifica della firma
            Signature dsa = null;
            try {
                dsa = Signature.getInstance("SHA256withDSA");
            } catch (NoSuchAlgorithmException ex) {
                System.out.println("Algoritmo non supportato");
            }
            dsa.initVerify(dsaPubKeyTsa);
            dsa.update(r.getInfo());  //r.info.getBytes?
            if(!dsa.verify(r.getSign()))
                throw new NotVerifiedSignException();
            //Decifratura RSA private key
            //Dovrei sapere chi è l'user
            Keychain userKeyChain = new Keychain(keychainFile, password);
            PrivateKey rsaPrivKeyUser = userKeyChain.getPrivateKey("Key/RSA/2048/Main");
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
            c.init(Cipher.DECRYPT_MODE, rsaPrivKeyUser);
            byte[] decrypted = c.doFinal(r.getInfo());
        }
    }
        
    public boolean verifyOffline(String docFile, String marcaFile){    
    
    }
         
    public boolean verifyOnline(String docFile, String marcaFile, String hashFile){
        
    }
}
