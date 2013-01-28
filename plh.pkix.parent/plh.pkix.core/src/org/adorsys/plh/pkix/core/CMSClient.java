package org.adorsys.plh.pkix.core;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;

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
	 * @param reciepientNamesX500
	 * @param inputStream
	 * @param outputStream
	 */
	public void sendFile(List<X500Name> reciepientNames, InputStream inputStream, OutputStream outputStream);

	/**
	 * Receives a file addressed to this client.
	 * @param inputStream
	 * @param outputStream
	 */
	public void receiveFile(InputStream inputStream, OutputStream outputStream);

}
