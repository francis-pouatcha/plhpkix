package org.adorsys.plh.pkix.client.sedent.identity;


public class UserNameClientIdentityProvider implements ClientIdentityProvider {

	@Override
	public String getClientIdentity() {
		return System.getProperty("user.name", "anonymous");
	}
	
	public static void main(String[] args){
		ClientIdentityProvider clientIdentityProvider = new UserNameClientIdentityProvider();
		String clientIdentity = clientIdentityProvider.getClientIdentity();
		System.out.println("Client Identity: " + clientIdentity);
	}

}
