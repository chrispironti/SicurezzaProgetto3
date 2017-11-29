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
 */
public class MerkleTree {
   
   private final String hashAlgorithm = "SHA-256";
   private byte[][] tree; //Array bidimensionale. Ogni elemento è un array di byte
   private int size;
   private MessageDigest md;
   
   public MerkleTree() throws NoSuchAlgorithmException{
    this.tree = new byte[15][];
    this.size = 0;
    this.md = MessageDigest.getInstance(this.hashAlgorithm);
}
   
   public void insert(byte[] elem, byte[] timestamp){
       this.md.update(DTSUtils.arrayConcat(elem, timestamp));
       this.tree[this.size] = md.digest();
       this.size += 1;
   }
   
   public byte[] buildMerkleTree() throws NoSuchAlgorithmException{
       int j = 8;
       for(int i = 0; i < 14 ; i+=2){
           this.md.update(DTSUtils.arrayConcat(tree[i],tree[i+1]));
           this.tree[j] = this.md.digest();
           this.size = this.size + 1;
           j += 1;
       }
       return tree[this.size - 1]; //Ritorna la radice, cioè HVi
   }
   
   public ArrayList<String> buildInfo(){
       ArrayList<String> info = new ArrayList<>();
       String str1 = "d";
       String str2 = "d";
       String str3 = "d";
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
           return "d";
       return "s";       
   }
   
   private String evalpos2(int k){
       if(k == 2 || k == 3 || k >= 6)
           return "s";
       return "d";
   }
   
   private String evalpos3(int k){
       if (k >=4)
           return "s";
       return "d";
   }
   
   public int getSize(){
       return this.size;
   }
}
