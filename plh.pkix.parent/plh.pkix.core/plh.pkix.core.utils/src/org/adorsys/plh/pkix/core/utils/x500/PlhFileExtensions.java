package org.adorsys.plh.pkix.core.utils.x500;

import org.apache.commons.lang3.StringUtils;

/**
 * Describes numerous types of file extensions used by this platform.
 * 
 * @author francis
 *
 */
public class PlhFileExtensions {

	private static final String PLH = ".plh";
	private static final String ENCRYPTED = ".encrypted";
	private static final String SIGNED = ".signed";
	private static final String PRIVATE_KEY = ".private";
	private static final String X509CERTIFICATE=".x509";
	private static final String KEYSTORE=".keystore";
	private static final String DEVICE_ACCOUNT=".device";
	private static final String USER_ACCOUNT=".account";
	
	/**
	 * Plain filed. Neither signed nor encrypted.
	 */
	public static final String FILE_PLAIN_EXT =  PLH;
	
	/**
	 * Describes a file encrypted by a key holder
	 */
	public static final String FILE_ENCRYPTED_EXT = ENCRYPTED + PLH;
	
	/**
	 * Describes a file signed by a key holder
	 */
	public static final String FILE_SIGNED_EXT = SIGNED + PLH;
	
	/**
	 * Describes a file signed and encrypted by a key holder
	 */
	public static final String FILE_SIGNED_ENCRYPTED_EXT =SIGNED + ENCRYPTED + PLH;
	
	/**
	 * Describes a password or public key encrypted private key
	 */
	public static final String PRIVATE_KEY_ENCRYPTED_EXT = PRIVATE_KEY + ENCRYPTED + PLH;
	
	/**
	 * Describes a private key signed and encrypted for storage.
	 */
	public static final String PRIVATE_KEY_SIGNED_ENCRYPTED_EXT = PRIVATE_KEY + SIGNED + ENCRYPTED + PLH;

	/**
	 * Describes a X509 certificate.
	 */
	public static final String CERTIFICATE_EXT = X509CERTIFICATE + PLH;
	
	/**
	 * A key store directory
	 */
	public static final String KEY_STORE_DIR_EXT = KEYSTORE + PLH;
	
	public static final String DEVICE_ACCOUNT_EXT = DEVICE_ACCOUNT + PLH;
	
	public static final String USER_ACCOUNT_EXT=USER_ACCOUNT+PLH;
	
	public static final boolean isPlhFile(String name){
		return StringUtils.endsWithIgnoreCase(name, PLH);
	}
	
}
