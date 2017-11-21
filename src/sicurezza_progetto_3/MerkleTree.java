/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;

/**
 * Utilities per la gestione del Merkel_Tree.
 * La classe deve supportare l'inserimento dei digest di ciascun utente nel livello
 * più basso e poi calcolare il valore dei digest ai livelli più alti e ritornare
 * l'HV al chiamante.
 * La classe calcola anche le informazioni necessarie a ciascun utente su come
 * ricostruire l'HV.
 * Ho già pensato a una semplice implementazione basata su Array e buttato giù 
 * qualcosa a penna, niente di che. * 
 */
public class MerkleTree {
    
   private byte[][] tree; //Array bidimensionale. Ogni elemento è un array di byte
   private String hash; //Algoritmo di hash del server TSA
   private int size;
   
   public MerkleTree(String hash){
    this.tree = new byte[15][];
    this.hash = hash;
    this.size = 0;
}
   
   public void insert(byte[] elem){
       this.tree[this.size] = elem;
       this.size += 1;
   }
   
   public byte[] buildMerkleTree() throws NoSuchAlgorithmException{
       int j = 8;
       MessageDigest md = MessageDigest.getInstance(hash);
       for(int i = 0; i < 14 ; i+=2){
           md.update(byteUtils.arrayConcat(tree[i],tree[i+1]));
           insert(md.digest());
           j += 1;
       }
       return tree[j]; //Ritorna la radice, cioè HVi
   }
   
   
   /*Costruisce le informazioni per ciascun utente per poter verificare HV. Ritorna
   un array di Arraylist, ove ogni elemento è un arraylist contenente tre tuple che,
   nell'ordine, dicono con chi e in che posizione concatenare il proprio hash per
   ottenere il root hash value.*/
   public ArrayList<String> buildInfo(){
       ArrayList<String> info = new ArrayList<>();
       String str1 = "dx";
       String str2 = "dx";
       String str3 = "dx";
       for(int k = 0; k < 8; k ++){
           int sibling = sibling(k);
           int father = parent(k);
           int grandfather = parent(father);
           String infostr = "";
           infostr += Base64.getEncoder().encodeToString(tree[sibling]) + "," + evalpos1(k)+",";
           infostr += Base64.getEncoder().encodeToString(tree[sibling(father)]) + "," + evalpos2(k)+",";
           infostr += Base64.getEncoder().encodeToString(tree[sibling(grandfather)]) + "," + evalpos3(k);
           info.add(infostr);
       }
       return info;
   }
   
   private int sibling(int pos){
       if(pos%2 == 0){
           return pos + 1;
       }else{
           return pos - 1;
       }
   }

   private int parent(int pos){
       if (pos%2 == 0){
           return 8+(pos/2);
       }
       else{
           return parent(sibling(pos));
       }
   }
   
   private String evalpos1(int k){
       if(k%2 == 0)
           return "dx";
       return "sx";       
   }
   
   private String evalpos2(int k){
       if(k == 2 || k == 3 || k >= 6)
           return "sx";
       return "dx";
   }
   
   private String evalpos3(int k){
       if (k >=4)
           return "sx";
       return "dx";
   }
   
   public int getSize(){
       return this.size;
   }
}
