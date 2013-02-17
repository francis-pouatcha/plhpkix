package org.adorsys.plh.pkix.client.services;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Simple storage service for the user.
 * 
 * All files stored by the user on this storage must be protected, encrypted 
 * and/or signed by the owner.
 * 
 * The storage service instance is configure on a per user account basis.
 * 
 * @author francis
 *
 */
public interface StorageService {

	/**
	 * Store the given information under path and returns a unique identifier that
	 * can be used to retrieve the information.
	 * 
	 * The path can be used by the server as unique identifier if conform. The mapping
	 * between the path and the returned identifier is responsibility of the caller.
	 * 
	 * The server will not check if the path already exists and might store many
	 * object under the same path.
	 * 
	 * @param path
	 * @param payload
	 * @param responseHandler : String the key referencing the object
	 * @param exceptionHandler : NoSpaceAvailableException: either object to big or assigned storage space full.
	 * @return
	 * 
	 */
	public void store(String path, OutputStream payload, 
			StorageResponseHandler<String> responseHandler, StorageResponseHandler<NoSpaceAvailableException> exceptionHandler);
	
	/**
	 * Replace the object identified with key with the passed object. The returned key
	 * might be different from the original one. It is the responsibility of the caller 
	 * to properly replace the key returned.
	 * 
	 * @param key
	 * @param path
	 * @param payload
	 * @param keyHandler
	 * @param noSpaceAvailableExceptionHandler
	 * @param objectNotFoundExceptionHandler
	 * @return
	 */
	public String replace(String key, String path, OutputStream payload,
			StorageResponseHandler<String> keyHandler, 
			StorageResponseHandler<NoSpaceAvailableException> noSpaceAvailableExceptionHandler,
			StorageResponseHandler<ObjectNotFoundException> objectNotFoundExceptionHandler);

	/**
	 * Write a file with the list of all keys owned by the user. Each key is on a proper line
	 * in the file.
	 * 
	 * The stream is closed by the client when this method returns.
	 * 
	 * @param inputStreamResponseHandler : result will be written into this steam.
	 * @return
	 */
	public void keys(StorageResponseHandler<InputStream> inputStreamResponseHandler);
	
	/**
	 * Returns the size of the object stored under this key.
	 * @param key
	 * @param sizeHandler
	 * @param objectNotFoundExceptionHandler
	 * @return
	 */
	public void size(String key, StorageResponseHandler<Long> sizeHandler,
			StorageResponseHandler<ObjectNotFoundException> objectNotFoundExceptionHandler);
	
	/**
	 * Writes the content of the file store under the given key in the
	 * given stream. Return the size of the file.
	 * 
	 * @param key
	 * @param inputStreamResponseHandler
	 * @param objectNotFoundExceptionHandler
	 * @return
	 */
	public void load(String key, StorageResponseHandler<InputStream> inputStreamResponseHandler, 
			StorageResponseHandler<ObjectNotFoundException> objectNotFoundExceptionHandler);
}
