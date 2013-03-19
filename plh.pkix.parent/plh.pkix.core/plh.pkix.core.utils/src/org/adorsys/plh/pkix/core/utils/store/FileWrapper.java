package org.adorsys.plh.pkix.core.utils.store;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * In order to protect user data on the file system, module reading and writing file
 * can implement the file container interface.
 * 
 * @author francis
 *
 */
public interface FileWrapper {
	
	/**
	 * Creates a new OnputString pointing to the underlying file.
	 * 
	 * @return
	 */
	public InputStream newInputStream();
	
	/**
	 * Creates a new outputStream to access the underlying file.
	 * @return
	 */
	public OutputStream newOutputStream();
	
	/**
	 * Returns the name of the file relative to the container directory.
	 * 
	 * @return
	 */
	public String getFileRelativePath();

	/**
	 * Deletes the underlying file
	 * @return
	 */
	public boolean delete();

	/**
	 * Checks if the underlying file exists
	 * @return
	 */
	public boolean exists();

	/**
	 * Get the name of the underlying file.
	 * 
	 * @return
	 */
	public String getName();
	
	public String getParent();
	
	/**
	 * Verifies the files underlying signature if any.
	 */
	public void integrityCheck();
	
	public String[] list();
	
	public FileWrapper newChild(String name);
	
	/**
	 * If this directory is protected by a key store, loads the certificate
	 * associated with the given public key identifier. If the passed
	 * public key identifier is null, return any certificate associated
	 * with a key entry.
	 * 
	 * The intention of this method is to help the application retrieve the 
	 * private key used to access this file.
	 * 
	 * @return
	public X509CertificateHolder loadKeyCertificate(String publicKeyIdentifier);	
	 */
	
	/**
	 * Returns the key store associated with this directory.
	 * @return
	 */
	public KeyStoreWraper getKeyStoreWraper();
}
