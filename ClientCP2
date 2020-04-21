import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.text.DefaultStyledDocument.ElementSpec;

public class ClientCP2 {
    private static volatile boolean waiting = true;
	private static FileOutputStream fileOutputStream = null;
	private static BufferedOutputStream bufferedFileOutputStream = null;
	private static byte [] encryptedNonce;

	public static void main(String[] args) {
		int numOfFiles = 1;
    	String filename = "100.txt";
    	String serverAddress = "localhost";
		int port = 2311;
		String[] listOfFilenames;
		
		if (args.length > 0) numOfFiles = Integer.parseInt(args[0]);
		if (numOfFiles>1){
			listOfFilenames = new String[numOfFiles];
			for(int i=1; i<args.length; i++){
				listOfFilenames[i-1] = args[i];
			}
			if (args.length > numOfFiles+1) serverAddress = args[numOfFiles+1];
			if (args.length > numOfFiles+2) port = Integer.parseInt(args[numOfFiles+2]);
		}
		else{
			listOfFilenames = new String[numOfFiles];
			listOfFilenames[0] = filename;
		}

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {
			// PublicKey pub_key = PublicKeyReader.get("public_key.der");
			// System.out.println(pub_key);

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			System.out.println("Authenticating...");

			// Send the authentication handshake request
			String request = "Hello SecStore please prove your identity";			
			toServer.writeInt(-1);
			toServer.writeInt(request.getBytes().length);
			toServer.write(request.getBytes());
			
			//send a nonce between 1000000 - 500000000
			Random r = new Random();
			int nonce = r.nextInt((500000000 - 1000000) + 1) + 1000000;
			toServer.writeInt(nonce);
			
			while(waiting == true){
				int packetType = fromServer.readInt();

				// If the packet is for authentication
				if (packetType == -1){
					System.out.println("Get Encrypted nonce");

					numBytes = fromServer.readInt();
					encryptedNonce = new byte[numBytes];
					fromServer.readFully(encryptedNonce, 0, numBytes);
				}
				else if(packetType == 0){
					fileOutputStream = makeFile(fromServer);
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
				}
				else if(packetType == 1){
					readFile(fileOutputStream, bufferedFileOutputStream, fromServer);
				}
			}

			InputStream fis = new FileInputStream("Client_CA.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
            PublicKey pub_key = CAcert.getPublicKey();

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, pub_key);
			byte[] recv_nonce_byte = cipher.doFinal(encryptedNonce);
			int recv_nonce = ByteBuffer.wrap(recv_nonce_byte).getInt();
			System.out.println(recv_nonce);

            //generate session key
            Cipher Encipher = Cipher.getInstance("RSA");
			Encipher.init(Cipher.ENCRYPT_MODE, pub_key);
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecretKey sharedKey = keyGen.generateKey();


			if (recv_nonce != nonce){
				//check failed
				closeConnection(toServer, fromServer);
			}
			else{
				//check succeeded
				System.out.println("Verified");
				// sendFilename(toServer, filename);
				// fileInputStream = new FileInputStream(filename);
				// bufferedFileInputStream = new BufferedInputStream(fileInputStream);

                // sendFile(fileInputStream, bufferedFileInputStream, toServer);
                
                //Sending shared key
                byte[] encryptedSessionKey = Encipher.doFinal(sharedKey.getEncoded());
                toServer.writeInt(5); //packet type sessionkey
                toServer.writeInt(encryptedSessionKey.length);
                toServer.write(encryptedSessionKey);
                toServer.flush();
				
				for(int i=0; i<numOfFiles; i++){
					System.out.println("Sending file: " + listOfFilenames[i]);
					// Send the filename
					sendFilename(toServer, listOfFilenames[i], sharedKey);
					//toServer.flush();

					// Open the file
					fileInputStream = new FileInputStream(listOfFilenames[i]);
					bufferedFileInputStream = new BufferedInputStream(fileInputStream);

					sendFile(fileInputStream, bufferedFileInputStream, toServer, sharedKey);
					// waiting = true;
					// while(waiting){
					// 	int packetType = fromServer.readInt();

					// 	// If the packet is for authentication
					// 	if (packetType == -1){
					// 		System.out.println("Get message");

					// 		numBytes = fromServer.readInt();
					// 		byte[] msg_byte = new byte[numBytes];
					// 		fromServer.readFully(msg_byte, 0, numBytes);
					// 		String msg = new String(msg_byte, StandardCharsets.UTF_8);
					// 		System.out.println(msg);
					// 		if(msg.equals("read")){
					// 			waiting = false;
					// 		}
					// 	}
					// }
				}
				System.out.println("Closing connection...");

				//Close connection
				closeConnection(toServer, fromServer);
			}

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}

	private static void closeConnection(DataOutputStream toServer, DataInputStream fromServer) throws Exception{
		String request = "bye";			
		toServer.writeInt(-1);
		toServer.writeInt(request.getBytes().length);
		toServer.write(request.getBytes());
		// Thread.sleep(1000000);
		System.out.println("right before close");
		fromServer.close();
		toServer.close();
	}

	private static void sendFilename(DataOutputStream toServer, String filename, SecretKey sharedKey) throws Exception{
        //cipher for session key
        Cipher fastCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        fastCipher.init(Cipher.ENCRYPT_MODE, sharedKey);
        byte[] encryptedFilename = fastCipher.doFinal(filename.getBytes());

        toServer.writeInt(0);
		toServer.writeInt(encryptedFilename.length);
		// System.out.println(filename.getBytes().length);
		toServer.write(encryptedFilename);
		// System.out.println(ByteBuffer.wrap(filename.getBytes()).getInt());
	}

	private static void sendFile(FileInputStream fileInputStream, BufferedInputStream bufferedFileInputStream
	, DataOutputStream toServer, SecretKey sharedKey) throws Exception{
        byte [] fromFileBuffer = new byte[117];
        //cipher for session key
        Cipher fastCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        fastCipher.init(Cipher.ENCRYPT_MODE, sharedKey);

		// Send the file
		for (boolean fileEnded = false; !fileEnded;) {
			int numBytes = bufferedFileInputStream.read(fromFileBuffer);
			fileEnded = numBytes < 117;

            byte[] encryptedBuffer = fastCipher.doFinal(fromFileBuffer);
			toServer.writeInt(1);
			toServer.writeInt(numBytes);
			toServer.write(encryptedBuffer);
			toServer.flush();
		}

		bufferedFileInputStream.close();
		fileInputStream.close();
	}

	private static FileOutputStream makeFile(DataInputStream fromServer) throws Exception{
		System.out.println("Receiving file...");

		int numBytes = fromServer.readInt();
		byte [] new_filename = new byte[numBytes];
		// Must use read fully!
		// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
		fromServer.readFully(new_filename, 0, numBytes);
		String file = new String(new_filename, 0, numBytes);
		System.out.println(file);

		fileOutputStream = new FileOutputStream("Client_"+new String(new_filename, 0, numBytes));
		return fileOutputStream;
	}

	private static void readFile(FileOutputStream fileOutputStream, BufferedOutputStream bufferedFileOutputStream, 
	DataInputStream fromServer) throws Exception{
		int numBytes = fromServer.readInt();
		// System.out.println(numBytes);
		byte [] block = new byte[numBytes];
		fromServer.readFully(block, 0, numBytes);
		// System.out.println(new String(block, StandardCharsets.UTF_8));

		if (numBytes > 0)
			bufferedFileOutputStream.write(block, 0, numBytes);

		if (numBytes < 117) {
			System.out.println("Closing connection...");

			if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
			if (bufferedFileOutputStream != null) fileOutputStream.close();
			waiting = false;
		}
	}
}
