package org.adorsys.plh.pkix.client.sedent.identity;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class HostAndUserClientIdentityProvider implements ClientIdentityProvider {

	@Override
	public String getClientIdentity() {
		String userName = new UserNameClientIdentityProvider().getClientIdentity();
		String localMac = "localhost";
		try {
			InetAddress localHost2 = InetAddress.getLocalHost();
			localMac = localHost2.getHostName();
		} catch (UnknownHostException e) {
			// do nothing
		}
		return userName+"@"+localMac;
	}

	
	public static void main(String[] args){
		ClientIdentityProvider clientIdentityProvider = new HostAndUserClientIdentityProvider();
		String clientIdentity = clientIdentityProvider.getClientIdentity();
		System.out.println("Client Identity: " + clientIdentity);
	}
}
