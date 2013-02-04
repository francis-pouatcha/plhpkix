package org.adorsys.plh.pkix.client.sedent.identity;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class HostAndDeviceIdentityProvider implements DeviceIdentityProvider {

	@Override
	public String getDeviceIdentity() {
		String userName = System.getProperty("user.name", "anonymous");
		String localMac = "localhost";
		try {
			InetAddress localHost2 = InetAddress.getLocalHost();
			localMac = localHost2.getHostName();
		} catch (UnknownHostException e) {
			// do nothing
		}
		return userName+"@"+localMac+".plhc";
	}

	
	public static void main(String[] args){
		DeviceIdentityProvider deviceIdentityProvider = new HostAndDeviceIdentityProvider();
		String deviceIdentity = deviceIdentityProvider.getDeviceIdentity();
		System.out.println("Device Identity: " + deviceIdentity);
	}
}
