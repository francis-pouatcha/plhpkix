package org.adorsys.plh.pkix.client.sedent.storage;

import java.util.ArrayList;
import java.util.List;

/**
 * Holds the chain of key storages needed to recover the private key of the 
 * client.
 * 
 * @author francis
 *
 */
public class KeyStorageChain {
	
	private List<String> serviceNames = new ArrayList<String>();

	public List<String> getServiceNames() {
		return serviceNames;
	}

	public void setServiceNames(List<String> serviceNames) {
		this.serviceNames = serviceNames;
	}
	
}
