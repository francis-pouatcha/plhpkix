package org.adorsys.plh.pkix.core.cmp;

import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;

public abstract class PlhCMPSystem {

	private static final String SYS_PROP_SERVER_NAME="org.adorys.plh.pkix.server.cmp.server_name";
	private static final String SYS_PROP_SERVER_EMAIL="org.adorys.plh.pkix.server.cmp.server_email";
	private static final String SYS_PROP_SERVER_PASSWORD="org.adorys.plh.pkix.server.cmp.server_password";

	public static final String PKIX_CMP_STRING = "application/pkixcmp";
	
	public static char[] getServerPassword(){
		return System.getProperty(SYS_PROP_SERVER_PASSWORD, "server_password").toCharArray();
	}
		
	public static X500Name getServerName(){
		String serverName = System.getProperty(SYS_PROP_SERVER_NAME, "server");
		String serverEmail = System.getProperty(SYS_PROP_SERVER_EMAIL, "server@plhpkix.com");
		return X500NameHelper.makeX500Name(serverName, serverEmail);
	}
}
