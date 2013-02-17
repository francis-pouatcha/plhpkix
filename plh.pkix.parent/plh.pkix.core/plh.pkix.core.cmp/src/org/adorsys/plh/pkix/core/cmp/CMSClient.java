package org.adorsys.plh.pkix.core.cmp;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Simple CMS (rfc 5652) based cryptographic message client.
 * 
 * @author francis
 *
 */
public interface CMSClient {
	/**
	 * Sends a file to the list of recipients specified.
	 * 
	 * @param issuerCN
	 * @param inputStream
	 * @param outputStream
	 * @param reciepientCommonNames
	 */
	public void sendFile(String issuerCN, InputStream inputStream, OutputStream outputStream, String... reciepientCommonNames);

	/**
	 * Receives a file addressed to this client.
	 * @param inputStream
	 * @param outputStream
	 */
	public void receiveFile(InputStream inputStream, OutputStream outputStream);

}
