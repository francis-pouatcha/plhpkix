package org.adorsys.plh.pkix.core.cmp;

import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Simple CMP (rfc 4210) based certificate management client.
 * 
 * @author francis
 *plh.pkix.core.cmp
 */
public interface CMPClient {
	/**
	 * Initializes an account and registers the account with the server.
	 * This certificate will be stored locally by the client and used for
	 * any request to the server.
	 */
	public void register(String userName, String emails, char[] accountStorePass,
			char[] accountKeyPass);
	/**
	 * Request the certification authority to certify this client. Any oder 
	 * client can be considered a certification authority. The self signed
	 * certificate of this client will be used as the model.
	 * 
	 * @param certAuthorityCN: the common name of the certification authority
	 * the message is addressed to.
	 */
	public void requestCertification(String certAuthorityCN);

	/**
	 * Fetch certificates signed by any of the certification authorities
	 * specified.
	 * 
	 * This framework uses the common name as the unique identifier for certificate owner.
	 * In the most common case we use the email of the certificate owner as common name.
	 * 
	 * @param subjectCN
	 * @param certAuthorityCN
	 */
	public void fetchCertificate(String subjectCN, String... certAuthorityCN);
	
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
