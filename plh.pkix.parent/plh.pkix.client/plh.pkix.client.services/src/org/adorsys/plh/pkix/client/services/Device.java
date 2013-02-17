package org.adorsys.plh.pkix.client.services;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Device is the terminal on which the account is being run. All account data
 * are stored encrypted on the device.
 * 
 * @author francis
 *
 */
public interface Device {

	public void signEncrypt(InputStream inputStream, 
			OutputStream outputStream) throws IOException;

	public void decrypVerify(InputStream inputStream, 
			OutputStream outputStream) throws IOException;

}
