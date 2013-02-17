package org.adorsys.plh.pkix.messaging.server;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.mail.internet.ContentType;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

@Path("/dbmessaging")
@Stateless
public class MessagingServer {

	@EJB
	private MessagingAccountRepository messagingAccountRepository;
	
	@POST
	@Path("/account")
	@Consumes("application/octet-stream")
//	@Produces("application/octet-stream")
	public Response createAccount(String emailStrict, String password){
		MessagingAccount messagingAccount = new MessagingAccount();
		messagingAccount.setEmail(emailStrict);
		messagingAccount.setPasswdHash(md5(password));
		return Response.status(Status.OK).build();
	}
	
	/**
	 * basic auth
	 * @param messageBytes
	 * @return
	 */
	@POST
	@Path("/send")
	@Consumes("application/octet-stream")
	@Produces("application/octet-stream")
	public Response send(byte[] messageBytes){
		return Response.status(Status.OK).build();
	}

	/**
	 * basic auth
	 * @param messageBytes
	 * @return
	 */
	@POST
	@Path("/send")
	@Consumes("application/octet-stream")
	@Produces("application/octet-stream")
	public Response recieve(){
		return Response.status(Status.OK).build();
	}
	
	private static String md5(String input) {
        String md5 = null;
        if(null == input) return null;
        try {
	        //Create MessageDigest object for MD5
	        MessageDigest digest = MessageDigest.getInstance("MD5");	         
	        //Update input string in message digest
	        digest.update(input.getBytes(), 0, input.length());
	        //Converts message digest value in base 16 (hex) 
	        md5 = new BigInteger(1, digest.digest()).toString(16);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return md5;
    }
}
