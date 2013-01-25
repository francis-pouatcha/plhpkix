package org.adorsys.plh.pkix.client.sedent.identity;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;


/**
 * Holds the client local key pair. Perform signatures and encryptions
 * on behalf of the client.
 * 
 * @author francis
 *
 */
public class Client {
	
	private File userDir = new File(System.getProperty("user.dir"));

	private String clientIdentity = new HostAndUserClientIdentityProvider().getClientIdentity();
	private File clientIdentityDir = new File(userDir, clientIdentity);

	private File storage = new File(clientIdentityDir, "storage");
	/**
	 * The identity of the client.
	 */
	
	public void store(String key, byte[] data){
		File file = new File(storage, key);
		try {
			FileUtils.writeByteArrayToFile(file, data);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
	
	public byte[] load(String key){
		File file = new File(storage, key);
		if(!file.exists()) return null;
		try {
			return FileUtils.readFileToByteArray(file);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
}
