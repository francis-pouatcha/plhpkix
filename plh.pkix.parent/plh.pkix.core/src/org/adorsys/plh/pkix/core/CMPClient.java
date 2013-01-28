package org.adorsys.plh.pkix.core;

import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Simple CMP (rfc 4210) based certificate management client.
 * 
 * @author francis
 *
 */
public interface CMPClient {
	
	/**
	 * Registers this client with the server. This happens once.
	 * As a result, the send back a certificate with client provided
	 * information.
	 * 
	 * This certificate will be stored locally by the client and used for
	 * any request to the server.
	 */
	public void register(String name, String email);
	
	/**
	 * Request the certification authority to certify this client. Any oder 
	 * client can be considered a certification authority, mean ca certify
	 * another client.
	 * 
	 * @param certAuthorityNameX500: the name of the certification authority
	 * the message is addressed to.
	 * @param mode: data sent for certification
	 */
	public void requestCertification(X500Name certAuthorityName, X509CertificateHolder model);
	
	/**
	 * Fetch a certificate signed by any of those certification authorities 
	 * from the server.
	 * 
	 * @param subjectNameX500
	 * @param certAuthorityNameX500
	 */
	public void fetchCertificate(X500Name subjectName, List<X500Name> certAuthorityName);
	
	/**
	 * Shows the list of certification request sent by other clients to this client.
	 * @return
	 */
	public List<X509CertificateHolder> listCertificationRequests();
	
	/**
	 * Produces a certificate for a certification request and sends it back to
	 * the requesting end entity.
	 * 
	 * @param certificationRequest
	 */
	public void certify(X509CertificateHolder certificationRequest);
	
	/**
	 * Reject a certification request.
	 */
	public void reject(X509CertificateHolder certificationRequest);

}
