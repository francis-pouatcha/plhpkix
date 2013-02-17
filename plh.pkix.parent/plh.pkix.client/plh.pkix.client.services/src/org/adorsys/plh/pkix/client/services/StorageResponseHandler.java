package org.adorsys.plh.pkix.client.services;

import java.util.List;

/**
 * Handle the response of a storage request.
 * 
 * @author francis
 *
 */
public interface StorageResponseHandler<T> {

	public void handleResponse(T object);
	
	public List<Exception> getExceptions();
}
