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
    
    private String hashAlgorithm; //Tipo di algoritmo hash che il server TSA deve usare.
    private int requestsNumber; //Numero di richieste nel Time Frame i
    private int IDNumber; //Inizializzato a 0, lo incrementiamo per ogni utente che fa le richieste
    private TSA TSAServer; //TSA Server
    private HashMap<String,ArrayList<TSAMessage>> requests; //map in cui la chiave è l'id dell'utente, il valore è una lista di richieste fatte da quell'utente
    private HashMap<String,ArrayList<TSAMessage>> responses;
    
    public TimestampManager(String hashAlgorithm, TSA TSAServer){
        this.hashAlgorithm = hashAlgorithm;
        this.TSAServer = TSAServer;
        this.requestsNumber = 0;
        this.IDNumber = 0;
        this.requests = null;
        this.responses = null;
    }
    
    public void newTimeframe(int requestsNumber){
        this.requestsNumber = 0;
        this.requests = new HashMap<>();
        this.responses = new HashMap<>();
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
    public void generateRequest(User user, byte[] message, String signType) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException{
        requestsNumber += 1;

        //Calcolo digest del messaggio
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Algoritmo non supportato");
        }
        md.update(message);
        byte[] msgDigest = md.digest();
        
        //Crea la richiesta
        TSAMessage req = new TSAMessage(user, msgDigest, signType);
        
        //Controllo nella map delle richieste
        //Se l'user ha già delle richieste aggiunge la richiesta nell'ArrayList
        if(requests.containsKey(user.getID())){
            requests.get(user.getID()).add(req);
        }
        else{ //Altrimenti crea un ArrayList con la richiesta dell'utente
            ArrayList<TSARequest> reqList = new ArrayList<>();
            reqList.add(req);
            requests.put(user.getID(), reqList);
        }
        
        if (requestsNumber == 8){
            this.sendRequests();
        }   
    }
    
    /*Manda la map di richieste al server TSA e salva le risposte nella mappa
    corrispondente della classe. Può essere chiamato in un qualunque momento dall'utente
    o automaticamente da generateRequest quando il numero max di richieste è stato raggiunto.
    */
    public void sendRequests() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException{
        responses=TSAServer.generateTimestamp(requests);      
    }
    
    /*
    Lancia un'eccezione per l utente i-esimo se 
    la sua marca non è verificata*/ 
    public void verifyResponse(User user) throws UnsupportedEncodingException, IOException, InvalidKeyException, SignatureException{
        //Per ogni richiesta associata all'user
        for (TSAResponse r: this.responses.get(user.getID())){
            //Verifica della firma
            Signature dsa = null;
            try {
                dsa = Signature.getInstance(r.signType);
            } catch (NoSuchAlgorithmException ex) {
                System.out.println("Algoritmo non supportato");
            }
            dsa.initVerify(); //TSA Public Key
            dsa.update(r.info);  //r.info.getBytes?
            Boolean verified=false;
            try {
                verified = dsa.verify(r.sign);
            } catch (SignatureException ex) {
                System.out.println("Errore nella verifica della firma");
            }
                
            if(verified){
                //TSAServer.rootHash;
                //TSAServer.superRootHash;
                //verifyInformation
            } else{
                System.out.println("Firma non verificata");
            }
            
        }
 
    }
}