package org.adorsys.plh.pkix.client.services;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Represents the user account.
 * 
 * @author francis
 *
 */
public interface Account {
	
	/**
	 * Store the information delivered provided by {@link InputStream}
	 * in the account store location on the underlying device.
	 * 
	 * @param inputStream
	 * @param relativeOutputPath
	 * @throws IOException
	 */
	public void deviceStoreTo(InputStream inputStream, 
			String relativeOutputPath) throws IOException;

	/**
	 * Load the information from the account storage on the
	 * underlying device.
	 * 
	 * @param relativeInputPath
	 * @param outputStream
	 * @throws IOException
	 */
	public void deviceLoadFrom(String relativeInputPath, 
			OutputStream outputStream) throws IOException;

}
