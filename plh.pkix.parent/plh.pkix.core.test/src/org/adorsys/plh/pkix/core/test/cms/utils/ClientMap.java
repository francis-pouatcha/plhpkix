package org.adorsys.plh.pkix.core.test.cms.utils;

import java.util.HashMap;
import java.util.Map;

/**
 * Type safety for the client Map
 * @author francis
 *
 */
public class ClientMap {

	// Client cache. Short cutting messaging functionality for test purpose
	private Map<String, MockCMPandCMSClient> clients = new HashMap<String, MockCMPandCMSClient>();
	
	public MockCMPandCMSClient getClient(String clientCN){
		return clients.get(clientCN.toLowerCase());
	}
	
	public void putClient(String clientCN, MockCMPandCMSClient client){
		clients.put(clientCN.toLowerCase(), client);
	}
}
