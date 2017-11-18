import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 *  This is a simple program to protect the users password.
    Copyright (C) 2017  Gil Vilela Correia

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

public class MyMatrix {

	private final static String folderName = ".myMatrix";//".myMatrix"
	private final static String macsFolder = ".macs";//".macs";
	private final static String userFile = ".user";//".user";
	private final static String name = "matrix";
	private static String pwd, salt, salt2;
	private static String [] [] matrix;
    private static Console console = System.console();


	public static void main (String [] args) throws NoSuchAlgorithmException, IOException {
		boolean ver;
		boolean firstTime = false;
		Scanner sc = new Scanner (System.in);
		String pwd2,aux,action;
		StringBuilder sb;
		byte [] buff,hash;
		BufferedWriter bwuFile;

		File dir = new File (new File(".").getAbsolutePath() + File.separator + folderName);
		File macDir = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + macsFolder);
		File uFile = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + userFile);
		if (!uFile.exists()){
			dir.mkdirs();
			macDir.mkdirs();
			firstTime = true;
		}

		MessageDigest md = MessageDigest.getInstance("SHA-256");

		if (firstTime){
			ver = false;
			while (!ver){
				pwd = new String(console.readPassword("This is your First Time, so write a secure password for this application:"));
				pwd2 = new String(console.readPassword("Confirm the password:"));
				//System.out.println("This is your First Time, so write a secure password for this application:");
				//pwd = sc.nextLine();
				//System.out.println("Confirm the password:");
				//pwd2 = sc.nextLine();
				if (!pwd.equals(pwd2)){
					System.err.println("The passwords didn't match, try again!");
				}
				else
					ver = true;
			}

			ver = false;
			while (!ver){
				System.out.println("For great security write 6 numbers randomly:");
				salt = sc.nextLine();
				if (salt.length() != 6)
					System.err.println("I said 6 numbers!");
				else
					ver = true;
			}

			ver = false;
			while (!ver){
				System.out.println("For greatest security write 6 numbers randomly:");
				salt2 = sc.nextLine();
				if (salt2.length() != 6)
					System.err.println("I said 6 numbers!");
				else
					ver = true;
			}
			sb = new StringBuilder();
			sb.append(pwd+":"+salt);
			aux = sb.toString();
			buff = DatatypeConverter.parseBase64Binary(aux);
			hash = md.digest(buff);
			bwuFile = new BufferedWriter (new FileWriter (uFile));
			aux = DatatypeConverter.printBase64Binary(hash);
			bwuFile.write(aux + ":" + salt + ":" + salt2);
			bwuFile.close();

			matrixCons(sc);
		}

		ver = true;
		while (ver){
			do{
				System.out.println("");
				System.out.println("      -v (view) | -c (confirm) | -u (update)"
					       + "\n-q (quit) | -about | -uninstall (uninstall myCipher)");
				action = sc.nextLine();
				if (!action.equals("-v") && !action.equals("-c") &&
						!action.equals("-u") && !action.equals("-q") &&
						!action.equals("-about") && !action.equals("-uninstall")){
					ver = false;
					System.err.println("Wrong Input!");
				}
				else
					ver = true;
			}
			while (!ver);

			switch (action){
			case "-v":
				if (!register(sc,uFile,md)){
					System.err.println("You have no permissions here!");
					break;
				}
				String [] positions;
				String result;
				int num;
				boolean fe = false;
				for (int i = 0; i < 3; i++){
					System.out.println("Wich position would you like to see? (ex. A2)");
					positions = sc.nextLine().split("");
					num = letterToNumber(positions[0]);
					if (positions.length == 2 || num >= 0 || num <= 25) {
						try{
							Integer.parseInt(positions[1]);
						}
						catch(NumberFormatException e){
							fe = true;
							System.err.println("Error with input format!");
						}
					}
					if (fe) { //format exception
						fe = false;
						i--;
					}
					else{
						result = decryptMatrix(fileToBytes(), letterToNumber(positions[0]), Integer.parseInt(positions[1])-1);
						if (result.equals("Wrong position!")){
							System.err.println(result);
							i--;
						}
						else{
							System.out.print("--> " + result + " <--");
							System.out.println("");
						}
					}
				}
				break;
				
			case "-c":
				if (!register(sc,uFile,md)){
					System.err.println("You have no permissions here!");
					break;
				}
				File signature;
				BufferedReader brc, brs;
				BufferedWriter bw;
				String par, compS;
				byte [] compare;
				if (!new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + "." + name + ".sig").exists()){
					String r;
					do {
						System.err.println(name + " doesn't have a signature, do you want to generate it?(y/n)");
						r = sc.nextLine();
					}
					while (!r.equals("y") && !r.equals("n"));
					if (r.equals("y")){
						signature = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + "." + name + ".sig");
						brc = new BufferedReader (new FileReader (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + name));
						bw = new BufferedWriter(new FileWriter(signature));
						par = brc.readLine();
						brc.close();
						hash = DatatypeConverter.parseBase64Binary(par);
						hash = md.digest(hash);
						bw.write(DatatypeConverter.printBase64Binary(hash));
						bw.close();
						System.out.println("Signature generated with success!");
					}
					else{
						System.out.println("Signature not generated.");
					}
					continue;
				}
				signature = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + "." + name + ".sig");
				brc = new BufferedReader (new FileReader (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + name));
				brs = new BufferedReader (new FileReader (signature));
				par = brc.readLine();
				brc.close();
				hash = DatatypeConverter.parseBase64Binary(par);
				hash = md.digest(hash);
				compS = brs.readLine();
				brs.close();
				compare = DatatypeConverter.parseBase64Binary(compS);
				if (Arrays.equals(hash, compare)){
					System.out.println(name + ": [V]");
				}
				else{
					System.out.print(name + ": [");
					System.err.print("X");
					System.out.println("]");
				}
				break;
				
			case "-u":
				if (!register(sc,uFile,md)){
				    System.err.println("You have no permissions here!");
				    break;
				}
				String ans = "";
				do{
					System.out.println("Would you like to update one position or the whole matrix? (pos|mat)");
					ans = sc.nextLine();
				}
				while (!ans.equals("pos") && !ans.equals("mat"));
				if (ans.equals("pos")){
					System.out.println("Wich position?");
					String pos = sc.nextLine();
					System.out.println("The new value:");
					String value = sc.nextLine();
					decryptMatrix(fileToBytes());
					matrix [letterToNumber(pos.split("")[0])][Integer.parseInt(pos.split("")[1])-1] = value;
					bytesToFile(ecryptMatrix(matrix[0].length));
				}
				else{
					matrixCons(sc);
				}
				break;

			case "-about":
			    System.out.println("MyCypher  Copyright (C) 2017  Gil Vilela Correia\nThis program comes with ABSOLUTELY NO WARRANTY; for details type `w'.\nThis is free software, and you are welcome to redistribute it\nunder certain conditions; type `c' for details.\ntype `q' to return to menu.");
			    while (true){
				aux = sc.nextLine();
				if (aux.equals("w")){
				    System.out.println("\nTHERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.\ntype `q' to return to menu.");
				}
				else if (aux.equals("c")){
				    System.out.println("IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.\ntype `q' to return to menu.");
				}
				else if(aux.equals("q")){
				    break;
				}
				else
				    System.err.println("Incorrect input!");
			    }
			    break;
				
			case "-uninstall":
				if (!register(sc,uFile,md)){
					System.err.println("You have no permissions here!");
					break;
				}
				System.out.println("");
				System.out.println("Are you sure that you want to uninstall myCipher? (y/n)");
				boolean noerase = false;
				while (true){
					aux = sc.nextLine();
					if (aux.equals("y"))
						break;
					else if (aux.equals("n")){
						noerase = true;
						break;
					}
					else
						System.err.println("Incorrect input!");
				}
				if (noerase)
					break;
				deleteDir(dir);
				System.out.println("Uninstall successful!");
			
			case "-q":
				System.out.println("Bye Bye :)");
				ver = false;
				sc.close();
				break;
				
			}
		}
	}

	private static void matrixCons(Scanner sc) throws NoSuchAlgorithmException, IOException {
		System.out.println ("What's the n of the matrix (nxn)?");
		int n = Integer.parseInt(sc.nextLine());
		String aux;
		matrix = new String [n] [n];
		for (int i = 0; i < n; i++){
			for (int j = 0; j < n; j++){
				System.out.println("Position " + numberToLetter(i) + (j+1) + ":");
				aux = sc.nextLine();
				matrix [i][j] = aux;
			}
		}
		bytesToFile(ecryptMatrix(n));
	}

	private static String numberToLetter (int i){
		int x = 'A' + i;
		char c = (char) x;
		String res = String.valueOf(c);
		return res;
	}

	private static int letterToNumber (String s){
		if (s.length() > 1)
			System.err.println("Wrong size string");
		char c = s.charAt(0);
		int x = c - 'A';
		return x;
	}

	private static boolean register (Scanner sc, File uFile, MessageDigest md) throws IOException{
		int i = 3;
		String aux;
		String [] x;
		byte [] compare, buff, hash;
		StringBuilder sb;
		BufferedReader brUFile;
		do{
			if (i < 3){
				System.err.println("Not that password");
				if (i == 0){
					return false;
				}
			}
			pwd = new String(console.readPassword("Password required:"));
			//System.out.println("Password required:");
			//pwd = sc.nextLine();
			brUFile = new BufferedReader (new FileReader (uFile));
			x = brUFile.readLine().split(":");
			aux = x[0];
			salt = x[1];
			salt2 = x[2];
			compare = DatatypeConverter.parseBase64Binary(aux);
			sb = new StringBuilder();
			sb.append(pwd+":"+salt);
			aux = sb.toString();
			buff = DatatypeConverter.parseBase64Binary(aux);
			hash = md.digest(buff);
			brUFile.close();
			i--;
		}
		while (!Arrays.equals(hash, compare));
		return true;
	}

	private static byte [] encrypt(byte [] plaintext,String pwd, String salt) throws NoSuchAlgorithmException{
		byte[] ciphertext = null;
		StringBuilder sb = new StringBuilder();
		String x = sb.append(salt+":"+pwd).toString();
		byte[]key = DatatypeConverter.parseBase64Binary(x);
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16);
		SecretKeySpec secret = new SecretKeySpec (key,"AES");
		try {
			Cipher cipherE = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipherE.init(Cipher.ENCRYPT_MODE, secret);
			ciphertext = cipherE.doFinal(plaintext);
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException 
				| NoSuchPaddingException e) {
			e.printStackTrace();
		}
		return ciphertext;
	}

	private static byte [] decrypt (byte [] ciphertext, String pwd, String salt) throws NoSuchAlgorithmException {
		byte [] plainbytes = null;
		StringBuilder sb = new StringBuilder();
		String x = sb.append(salt+":"+pwd).toString();
		byte[]key = DatatypeConverter.parseBase64Binary(x);
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16);
		SecretKeySpec secret = new SecretKeySpec (key,"AES");
		try{
			Cipher cipherD = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipherD.init(Cipher.DECRYPT_MODE, secret);
			plainbytes = cipherD.doFinal(ciphertext);
		} catch (InvalidKeyException | NoSuchAlgorithmException 
				| NoSuchPaddingException 
				| IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return plainbytes;
	}

	private static byte [] ecryptMatrix(int n) throws NoSuchAlgorithmException {
		StringBuilder sb = new StringBuilder ();
		for (int i = 0; i < n; i++){
			for (int j = 0; j < n; j++){
				sb.append(matrix[i][j] + ":");
			}
		}
		String str = sb.toString();
		return encrypt (str.getBytes(),pwd,salt2);
	}

	private static String decryptMatrix(byte[] ciphertext, int y, int x) throws NoSuchAlgorithmException {
		byte [] decrypted;
		decrypted = decrypt (ciphertext,pwd,salt2);
		String [] array = new String (decrypted).split(":");
		int size = (int) Math.sqrt(array.length);
		if (y > (size-1) || x > (size-1))
			return "Wrong position!";
		return array [y*size+x];
	}
	
	private static void decryptMatrix(byte[] ciphertext) throws NoSuchAlgorithmException {
		byte [] decrypted;
		decrypted = decrypt (ciphertext,pwd,salt2);
		String [] array = new String (decrypted).split(":");
		int size = (int) Math.sqrt(array.length);
		int p = 0;
		matrix = new String [size][size];
		for (int i = 0; i < size; i++){
			for (int j = 0; j < size; j++){
				matrix[i][j] = array [p];
			}
		}
	}
	
	private static void bytesToFile(byte[] encrypted) throws IOException, NoSuchAlgorithmException {
		String e1;
		byte [] hash;
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		File novo = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + name);
		File sig = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + "." + name + ".sig");
		BufferedWriter bw = new BufferedWriter (new FileWriter(novo));
		bw.write(DatatypeConverter.printBase64Binary(encrypted));
		bw.flush();
		bw.close();
		BufferedReader brsig = new BufferedReader (new FileReader (novo));
		e1 = brsig.readLine();
		brsig.close();
		bw = new BufferedWriter (new FileWriter (sig));
		hash = md.digest(DatatypeConverter.parseBase64Binary(e1));
		bw.write(DatatypeConverter.printBase64Binary(hash));
		bw.close();
		System.out.println("Account saved with success!");
	}

	private static byte [] fileToBytes() throws IOException, NoSuchAlgorithmException {
		File toread = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + name);
		BufferedReader br = new BufferedReader (new FileReader(toread));
		String userb = br.readLine();
		br.close();
		return DatatypeConverter.parseBase64Binary(userb);
	}
	
	private static void deleteDir(File file) {
		File[] contents = file.listFiles();
		if (contents != null) {
			for (File f : contents) {
				deleteDir(f);
			}
		}
		file.delete();
	}
}
