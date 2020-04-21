import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

import javax.crypto.Cipher;


public class ServerCP1 {
    private static FileOutputStream fileOutputStream = null;

	public static void main(String[] args) {

    	int port = 2311;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		// FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			// System.out.println(pri_key);
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());
            
            PrivateKey pri_key = PrivateKeyReader.get("private_key.der");

            Cipher RSADeCipherPrivate = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            RSADeCipherPrivate.init(Cipher.DECRYPT_MODE, pri_key);

			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();
				System.out.println("packetType: " + packetType);

				// If the packet is for authentication
				if (packetType == -1){
					System.out.println("packetType: " + packetType);

					int numBytes = fromClient.readInt();
					byte [] request = new byte[numBytes];
                    fromClient.readFully(request, 0, numBytes);

					String requestType = new String(request, StandardCharsets.UTF_8);
					System.out.println(requestType);
					if (requestType.equals("Hello SecStore please prove your identity")){
						int nonce = fromClient.readInt();
						System.out.println(nonce);
						Cipher cipher = Cipher.getInstance("RSA");
						cipher.init(Cipher.ENCRYPT_MODE, pri_key);
						byte[] encryptedNonce = cipher.doFinal(BigInteger.valueOf(nonce).toByteArray());
						toClient.writeInt(-1);
						toClient.writeInt(encryptedNonce.length);
						toClient.write(encryptedNonce);

						//Send filename
						String filename = "CA.crt";
						sendFilename(toClient, filename);

						//Send file
						FileInputStream fis = new FileInputStream(filename);
						BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fis);

						sendFile(fis, bufferedFileInputStream, toClient);

						// byte [] fromFileBuffer = new byte[117];

						// // Send the file
						// for (boolean fileEnded = false; !fileEnded;) {
						// 	numBytes = bufferedFileInputStream.read(fromFileBuffer);
						// 	fileEnded = numBytes < 117;

						// 	toClient.writeInt(1);
						// 	toClient.writeInt(numBytes);
						// 	toClient.write(fromFileBuffer);
						// 	toClient.flush();
						// }

						// bufferedFileInputStream.close();
						// fis.close();
					}
					else if(requestType.equals("bye")){
						// read(toClient, "read");
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}

				// If the packet is for transferring the filename
				if (packetType == 0) {
					FileOutputStream fileOutputStream = null;
					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					// System.out.println(numBytes);
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);
                    
                    //Decypher file name
                    byte[] newFilename = RSADeCipherPrivate.doFinal(filename);

					System.out.println(new String(newFilename, 0, newFilename.length));
					fileOutputStream = new FileOutputStream("Server_"+new String(newFilename, 0, newFilename.length));
					// fileOutputStream = makeFile(fromClient);
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {
					int numBytes = fromClient.readInt();
					byte [] block = new byte[128];
                    fromClient.readFully(block, 0, 128);
                    
                    //Decypher each chunk of file
                    byte[] blockbytes = RSADeCipherPrivate.doFinal(block);

					if (numBytes > 0)
						bufferedFileOutputStream.write(blockbytes, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) {
							bufferedFileOutputStream.close();
							// fileOutputStream.close();
						}
						// if (bufferedFileOutputStream != null) fileOutputStream.close();
						// System.out.println(fromClient.readInt());
						// read(toClient, "read");
					}
					// readFile(fileOutputStream, bufferedFileOutputStream, fromClient, toClient);
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

	private static void read(DataOutputStream toClient, String msg) throws Exception{
		toClient.writeInt(-1);
		toClient.writeInt(msg.getBytes().length);
		toClient.write(msg.getBytes());
	}

	private static void sendFilename(DataOutputStream toClient, String filename) throws Exception{
		toClient.writeInt(0);
		toClient.writeInt(filename.getBytes().length);
		toClient.write(filename.getBytes());
	}

	private static void readFile(FileOutputStream fileOutputStream, BufferedOutputStream bufferedFileOutputStream, 
	DataInputStream fromClient, DataOutputStream toClient) throws Exception{
		int numBytes = fromClient.readInt();
		byte [] block = new byte[numBytes];
		fromClient.readFully(block, 0, numBytes);

		if (numBytes > 0)
			bufferedFileOutputStream.write(block, 0, numBytes);

		if (numBytes < 117) {
			System.out.println("Closing connection...");

			if (bufferedFileOutputStream != null) {
				bufferedFileOutputStream.close();
			}
			if (bufferedFileOutputStream != null) fileOutputStream.close();
			// System.out.println(fromClient.readInt());
			// read(toClient, "read");
		}
	}

	private static FileOutputStream makeFile(DataInputStream fromClient) throws Exception{
		System.out.println("Receiving file...");

		int numBytes = fromClient.readInt();
		// System.out.println(numBytes);
		byte [] filename = new byte[numBytes];
		// Must use read fully!
		// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
		fromClient.readFully(filename, 0, numBytes);

		System.out.println(new String(filename, 0, numBytes));
		fileOutputStream = new FileOutputStream("Server_"+new String(filename, 0, numBytes));
		return fileOutputStream;
	}

	private static void sendFile(FileInputStream fileInputStream, BufferedInputStream bufferedFileInputStream
	, DataOutputStream toClient) throws Exception{
		byte [] fromFileBuffer = new byte[117];

		// Send the file
		for (boolean fileEnded = false; !fileEnded;) {
			int numBytes = bufferedFileInputStream.read(fromFileBuffer);
			// System.out.println(numBytes);
			// System.out.println(new String(fromFileBuffer, StandardCharsets.UTF_8));
			fileEnded = numBytes < 117;

			toClient.writeInt(1);
			toClient.writeInt(numBytes);
			toClient.write(fromFileBuffer);
			toClient.flush();
		}

		bufferedFileInputStream.close();
		fileInputStream.close();
	}
}