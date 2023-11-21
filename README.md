Vigener
import java.util.*;
class HelloWorld {
// Generates the key in cyclic manner until it's length is not equal to the length of plain text
static String generateKey(String str, String key)
{
    int x = str.length();
    for (int i = 0; ; i++)
    {
        if (x == i)
            i = 0;
        if (key.length() == str.length())
            break;
        key+=(key.charAt(i));
    }
    return key;
}

// Encrypted text is generated with the help of the key
static String cipherText(String str, String key)
{
    String cipher_text="";
 
    for (int i = 0; i < str.length(); i++)
    {
        // converting in range 0-25
        int x = (str.charAt(i) + key.charAt(i)) %26;
 
        // convert into alphabets(ASCII)
        x += 'A';
 
        cipher_text+=(char)(x);
    }
    return cipher_text;
}
 
// Decrypts the cipher text
static String originalText(String cipher_text, String key)
{
    String orig_text="";
 
    for (int i = 0 ; i < cipher_text.length() &&
                            i < key.length(); i++)
    {
        // converting in range 0-25
        int x = (cipher_text.charAt(i) -
                    key.charAt(i) + 26) %26;
 
        // convert into alphabets(ASCII)
        x += 'A';
        orig_text+=(char)(x);
    }
    return orig_text;
}
 
// Lower case character to Upper case
static String LowerToUpper(String s)
{
    StringBuffer str =new StringBuffer(s);
    for(int i = 0; i < s.length(); i++)
    {
        if(Character.isLowerCase(s.charAt(i)))
        {
            str.setCharAt(i, Character.toUpperCase(s.charAt(i)));
        }
    }
    s = str.toString();
    return s;
}
 
 // Driver Code
public static void main(String[] args)
{
    Scanner poly = new Scanner(System.in);
    
    System.out.println("Enter Plain text:");
    String Str = poly.next();
    String str = LowerToUpper(Str);
    
    System.out.println("Enter the Keyword:");
    String Keyword = poly.next();
    String keyword = LowerToUpper(Keyword);
 
    String key = generateKey(str, keyword);
    String cipher_text = cipherText(str, key);
 
    System.out.println("Cipher Text after Encryption: " + cipher_text);
    System.out.println("Plain Text after Decryption:" + originalText(cipher_text, key));
    }
}


Columnar
import java.util.Scanner;

public class SimpleColumnarTransposition {

    // Encryption function
    public static String encrypt(String plaintext, String key) {
        int keyLength = key.length();
        int textLength = plaintext.length();

        // Calculate the number of rows required in the matrix
        int numRows = (int) Math.ceil((double) textLength / keyLength);

        // Create a 2D array to hold the characters
        char[][] matrix = new char[numRows][keyLength];

        // Fill the matrix with the plaintext characters
        int textIndex = 0;
        for (int i = 0; i < numRows; i++) {
            for (int j = 0; j < keyLength; j++) {
                if (textIndex < textLength) {
                    matrix[i][j] = plaintext.charAt(textIndex);
                    textIndex++;
                } else {
                    matrix[i][j] = ' ';
                }
            }
        }

        // Encrypt the message by reading columns according to the key
        StringBuilder ciphertext = new StringBuilder();
        for (int j = 0; j < keyLength; j++) {
            int col = key.indexOf(key.charAt(j));
            for (int i = 0; i < numRows; i++) {
                ciphertext.append(matrix[i][col]);
            }
        }

        return ciphertext.toString();
    }

    // Decryption function
    public static String decrypt(String ciphertext, String key) {
        int keyLength = key.length();
        int textLength = ciphertext.length();

        // Calculate the number of rows required in the matrix
        int numRows = (int) Math.ceil((double) textLength / keyLength);

        // Calculate the number of characters in the last row
        int lastRowLength = textLength % keyLength;
        if (lastRowLength == 0) {
            lastRowLength = keyLength;
        }

        // Create a 2D array to hold the characters
        char[][] matrix = new char[numRows][keyLength];

        // Fill the matrix with the ciphertext characters
        int textIndex = 0;
        for (int j = 0; j < keyLength; j++) {
            int col = key.indexOf(key.charAt(j));
            for (int i = 0; i < numRows; i++) {
                if (i == numRows - 1 && j >= lastRowLength) {
                    matrix[i][col] = ' ';
                } else {
                    matrix[i][col] = ciphertext.charAt(textIndex);
                    textIndex++;
                }
            }
        }

        // Decrypt the message by reading rows
        StringBuilder plaintext = new StringBuilder();
        for (int i = 0; i < numRows; i++) {
            for (int j = 0; j < keyLength; j++) {
                plaintext.append(matrix[i][j]);
            }
        }

        return plaintext.toString().trim();
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the plaintext: ");
        String plaintext = scanner.nextLine();

        System.out.print("Enter the encryption key: ");
        String key = scanner.nextLine();

        // Encryption
        String ciphertext = encrypt(plaintext, key);
        System.out.println("Encrypted Message: " + ciphertext);

        // Decryption
        String decryptedText = decrypt(ciphertext, key);
        System.out.println("Decrypted Message: " + decryptedText);
    }
}
Rail fence
public class RailFenceCipher {

    // Function to encrypt a message using Rail Fence Transposition
    static String encrypt(String message, int rails) {
        // Create a 2D array to represent the rail fence structure
        char[][] railFence = new char[rails][message.length()];
        
        // Initialize the array with space characters
        for (int i = 0; i < rails; i++) {
            for (int j = 0; j < message.length(); j++) {
                railFence[i][j] = ' ';
            }
        }
        
        // Fill in the rail fence with the message characters
        int row = 0;
        boolean down = false;
        
        for (int i = 0; i < message.length(); i++) {
            railFence[row][i] = message.charAt(i);
            
            // Change direction when reaching the top or bottom rail
            if (row == 0 || row == rails - 1) {
                down = !down;
            }
            
            // Move to the next row in the appropriate direction
            if (down) {
                row++;
            } else {
                row--;
            }
        }
        
        // Read the encrypted message row by row
        StringBuilder encryptedMessage = new StringBuilder();
        for (int i = 0; i < rails; i++) {
            for (int j = 0; j < message.length(); j++) {
                if (railFence[i][j] != ' ') {
                    encryptedMessage.append(railFence[i][j]);
                }
            }
        }
        
        return encryptedMessage.toString();
    }
  public static String decryptRailFence(String cipherText, int rails) {
        int textLength = cipherText.length();
        char[][] railMatrix = new char[rails][textLength];
        boolean down = false;
        int row = 0, col = 0;

        // Initialize the rail matrix with placeholders
        for (int i = 0; i < rails; i++) {
            for (int j = 0; j < textLength; j++) {
                railMatrix[i][j] = ' ';
            }
        }

        // Fill the rail matrix with the cipherText
        for (int i = 0; i < textLength; i++) {
            if (row == 0 || row == rails - 1) {
                down = !down;
            }

            railMatrix[row][col] = '*';
            col++;

            if (down) {
                row++;
            } else {
                row--;
            }
        }

        // Reconstruct the plainText
        int index = 0;
        char[] plainText = new char[textLength];
        for (int i = 0; i < rails; i++) {
            for (int j = 0; j < textLength; j++) {
                if (railMatrix[i][j] == '*' && index < textLength) {
                    plainText[j] = cipherText.charAt(index);
                    index++;
                }
            }
        }

        return new String(plainText);
    }


    public static void main(String[] args) {
        String message = "HELLOWORLD";
        int rails = 3;

        String encryptedMessage = encrypt(message, rails);
        System.out.println("Encrypted Message: " + encryptedMessage);

String decryptedText = decryptRailFence(cipherText, rails);
        System.out.println("Decrypted Message: " + decryptedText);

    }
}
RSA
// Java Program to Implement the RSA Algorithm
import java.math.*;
import java.util.*;

class RSA {
	public static void main(String args[])
	{
		int p, q, n, z, d = 0, e, i;
		// The number to be encrypted and decrypted
		int m = 12;
		double c;
		BigInteger decmsg;

		p = 3; // 1st prime number
		q = 11; // 2nd prime number
		n = p * q;
		z = (p - 1) * (q - 1); // eulers totient function phi(n)
		System.out.println("the value of z = " + z);
		// e is for public key exponent
		for (e = 2; e < z; e++) {

			if (gcd(e, z) == 1) {
				break;
			}
		}
		System.out.println("the value of e = " + e);
		for (i = 0; i <= 9; i++) {
			int x = 1 + (i * z);

			// d is for private key exponent
			if (x % e == 0) {
				d = x / e;
				break;
			}
		}
		System.out.println("the value of d = " + d);
		
		System.out.println("the public key is:" + "{"+e+","+n+"}");
		System.out.println("the private key is:" + "{"+d+","+n+"}");
		
		c = (Math.pow(m, e)) % n; // for encryption
		System.out.println("Encrypted message is : " + c);
		// converting int value of n to BigInteger
		BigInteger N = BigInteger.valueOf(n);

		// converting float value of c to BigInteger
		BigInteger C = BigDecimal.valueOf(c).toBigInteger();
		decmsg = (C.pow(d)).mod(N); //for decryption
		System.out.println("Decrypted message is : "
						+ decmsg);
	}

	static int gcd(int e, int z)
	{
		if (e == 0)
			return z;
		else
			return gcd(z % e, e);
	}
}






Morse Code
import java.util.Scanner;

public class MorseLock {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Morse with Caeser Cipher");
        System.out.print("Enter your message: ");
        String message = scanner.nextLine().toUpperCase();

        System.out.print("Enter Caesar cipher key (an integer): ");
        int caesarKey = scanner.nextInt();
        scanner.nextLine();

        // Custom Morse code mapping
        String[] morseCodeMapping = {
            ".-", "-...", "-.-.", "-..", ".", "..-.", "--.", "....", "..", ".---", "-.-",
            ".-..", "--", "-.", "---", ".--.", "--.-", ".-.", "...", "-", "..-", "...-", ".--",
            "-..-", "-.--", "--..", " " // Include space for delimiter
        };

        // Encryption
        String encryptedMessage = encrypt(message, caesarKey, morseCodeMapping);
        System.out.println("Encrypted Message: " + encryptedMessage);

        // Decryption
        String decryptedMessage = decrypt(encryptedMessage, caesarKey, morseCodeMapping);
        System.out.println("Decrypted Message: " + decryptedMessage);

        scanner.close();
    }

    // Encrypt a message using MorseLock
    public static String encrypt(String message, int caesarKey, String[] morseCodeMapping) {
        StringBuilder encryptedMessage = new StringBuilder();
        for (char ch : message.toCharArray()) {
            if (Character.isLetter(ch)) {
                // Apply Caesar cipher
                ch = (char) ('A' + (ch - 'A' - caesarKey + 26) % 26);
            }
            if (ch == ' ') {
                encryptedMessage.append(morseCodeMapping[26]); // Use space as delimiter
            } else if (Character.isLetter(ch) || Character.isDigit(ch)) {
                int index = ch - 'A'; // Assuming uppercase letters only
                encryptedMessage.append(morseCodeMapping[index]);
                encryptedMessage.append(' '); // Separate Morse code characters
            }
        }
        return encryptedMessage.toString();
    }

    // Decrypt a MorseLock message
    public static String decrypt(String encryptedMessage, int caesarKey, String[] morseCodeMapping) {
        StringBuilder decryptedMessage = new StringBuilder();
        String[] morseSegments = encryptedMessage.split(" ");
        for (String segment : morseSegments) {
            int index = -1;
            for (int i = 0; i < morseCodeMapping.length; i++) {
                if (morseCodeMapping[i].equals(segment)) {
                    index = i;
                    break;
                }
            }
            if (index == 26) {
                decryptedMessage.append(' '); // Restore space delimiter
            } else if (index >= 0) {
                char ch = (char) ('A' + (index + caesarKey) % 26);
                decryptedMessage.append(ch);
            }
        }
        return decryptedMessage.toString();
    }
}

SHA 1
Python
import hashlib

input_str = input("Enter a string: ")

# Create a SHA-1 hash object
sha1 = hashlib.sha1()

# Update the hash object with the input string encoded as bytes
sha1.update(input_str.encode('utf-8'))

# Get the hexadecimal representation of the digest
hashed_str = sha1.hexdigest()

print("Hash value for", input_str,"is:", hashed_str)


Java
// SHA-1
import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class main {
	public static String encryptThisString(String input)
	{
		try {
			// getInstance() method is called with algorithm SHA-1
			MessageDigest md = MessageDigest.getInstance("SHA-1");

			// digest() method is called to calculate message digest of the input string returned as array of byte
			byte[] messageDigest = md.digest(input.getBytes());

			// Convert byte array into signum representation
			BigInteger no = new BigInteger(1, messageDigest);

			// Convert message digest into hex value
			String hashtext = no.toString(16);

			// Add preceding 0s to make it 32 bit
			while (hashtext.length() < 32) {
				hashtext = "0" + hashtext;
			}

			// return the HashText
			return hashtext;
		}

		// For specifying wrong message digest algorithms
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	// Driver code
	public static void main(String args[]) throws NoSuchAlgorithmException
	{
	    Scanner sc= new Scanner(System.in);
		System.out.println("Input Text: ");
		String s1= sc.nextLine();  
		System.out.println("HashCode Generated by SHA-1 for: ");
		System.out.println("\n" + s1 + " : " + encryptThisString(s1));
	}
}

DSS
import java.security.*;

public class DS {

    public static void main(String[] args) throws Exception {

        // Generate key pair
        KeyPair keyPair = generateKeyPair();

        // Create a message
        String message = "Cryptography and Network Security";

        // Generate hash value
        byte[] hashValue = generateHash(message);

        // Generate digital signature
        byte[] digitalSignature = generateDigitalSignature(hashValue, keyPair.getPrivate());

        // Print message, hash value, keys, signature, and verification status
        System.out.println("Original Message: " + message);
        System.out.println("Hash Value: " + bytesToHex(hashValue));
        System.out.println("Public Key (e): " + ((PublicKey) keyPair.getPublic()).getEncoded());
        System.out.println("Public Key (n): " + keyPair.getPublic().getAlgorithm());
        System.out.println("Private Key (d): " + ((PrivateKey) keyPair.getPrivate()).getEncoded());
        System.out.println("Digital Signature: " + bytesToHex(digitalSignature));

        // Verify digital signature
        boolean isVerified = verifyDigitalSignature(hashValue, digitalSignature, keyPair.getPublic());

        // Print verification status
        System.out.println("Signature Verification: " + isVerified);
    }

    // Generate key pair
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    // Generate digital signature
    public static byte[] generateDigitalSignature(byte[] hashValue, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(hashValue);
        return signature.sign();
    }

    // Generate hash value
    public static byte[] generateHash(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        return digest.digest(message.getBytes());
    }

    // Verify digital signature
    public static boolean verifyDigitalSignature(byte[] hashValue, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA1withRSA");
        verifier.initVerify(publicKey);
        verifier.update(hashValue);
        return verifier.verify(signature);
    }

    // Convert bytes to hexadecimal
    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}
Elgamal
import java.math.BigInteger;
import java.util.Random;

public class ElGamalEncryption {
    private static Random random = new Random();
    
    public static void main(String[] args) {
        String msg = "encryption";
        System.out.println("Original Message: " + msg);
        BigInteger q = getRandomBigInteger(BigInteger.TEN.pow(20), BigInteger.TEN.pow(50));
        BigInteger g = getRandomBigInteger(BigInteger.TWO, q);
        BigInteger privateKey = generateKey(q);
        BigInteger h = g.modPow(privateKey, q);
        System.out.println("g used: " + g);
        System.out.println("g^a used: " + h);
        Object[] encryptedMessage = encrypt(msg, q, h, g);
        BigInteger p = (BigInteger) encryptedMessage[1];
        String decryptedMessage = decrypt((BigInteger[]) encryptedMessage[0], p, privateKey, q);
        System.out.println("Decrypted Message: " + decryptedMessage);
        
    }
    
    private static BigInteger getRandomBigInteger(BigInteger lower, BigInteger upper) {
        BigInteger range = upper.subtract(lower);
        int bits = range.bitLength();
        BigInteger randomNumber;
        do {
            randomNumber = new BigInteger(bits, random);
            
        }while (randomNumber.compareTo(range) >= 0);
        return randomNumber.add(lower); }
        
        private static BigInteger generateKey(BigInteger q) {
            BigInteger key = getRandomBigInteger(BigInteger.TEN.pow(20), q);
            while (!key.gcd(q).equals(BigInteger.ONE)) {
                key = getRandomBigInteger(BigInteger.TEN.pow(20), q);
                
            }
            return key;
            
        }
        
        private static Object[] encrypt(String msg, BigInteger q, BigInteger h, BigInteger g) {
            BigInteger[] enMsg = new BigInteger[msg.length()];
            BigInteger k = generateKey(q);
            BigInteger s = h.modPow(k, q);
            BigInteger p = g.modPow(k, q);
            for (int i = 0; i < msg.length(); i++) {
                enMsg[i] = s.multiply(BigInteger.valueOf(msg.charAt(i)));
                
            }
            System.out.println("g^k used: " + p);
            System.out.println("g^ak used: " + s);
            return new Object[]{enMsg, p};
            
        }
        
        private static String decrypt(BigInteger[] enMsg, BigInteger p, BigInteger key, BigInteger q) {
            StringBuilder drMsg = new StringBuilder();
            BigInteger h = p.modPow(key, q);
            for (BigInteger value : enMsg) {
                drMsg.append((char) (value.divide(h)).intValue());
                
            }
            return drMsg.toString();
            
        }
    
}

Image encryption
import cv2
import numpy as np
from numpy import random

#Load original image
demo = cv2.imread("/content/cat.jpg")
r, c, t = demo.shape

#Create random key
key = random.randint(256, size = (r, c, t))

#Encryption
enc = demo ^ key

#decryption
dec = enc ^ key
cv2.imwrite("encrypted.jpg", enc)
cv2.imwrite("decrypted.jpg", dec)
cv2.imwrite("key.png", key)


