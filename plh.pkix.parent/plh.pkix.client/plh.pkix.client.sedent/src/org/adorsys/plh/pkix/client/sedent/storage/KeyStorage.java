package org.adorsys.plh.pkix.client.sedent.storage;

/**
 * Store cryptographic keys and passwords based on the underlying 
 * algorithm.
 * 
 * @author francis
 *
 */
public interface KeyStorage {

	/**
	 * Retrieve the key stored in data. It might eventually
	 * use data to retrieve the real payload.
	 * 
	 * @param data
	 * @return
	 */
	public byte[] loadKey(byte[] data);
}
