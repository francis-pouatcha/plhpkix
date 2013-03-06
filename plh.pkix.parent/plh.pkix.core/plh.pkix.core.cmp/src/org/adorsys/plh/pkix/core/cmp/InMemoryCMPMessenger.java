package org.adorsys.plh.pkix.core.cmp;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

/**
 * Test cmp messenger.
 * 
 * Holds a request and response queue for each end entity. Uses the sender's public
 * key identifier to identify the sender. Note that a sender can have many certificates.
 * 
 * @author francis
 *
 */
public class InMemoryCMPMessenger implements CMPMessenger {

	/**
	 * The endpoint map
	 */
	private Map<String, CMPMessageEndpoint> publicKeyIdentifier2EndPoint = new HashMap<String, CMPMessageEndpoint>();
	// associates email with end entity identifier.
	private Map<String, String> email2EndEntityIdentifiers = new HashMap<String, String>();
	
	private Map<String, String> publicKeyId2ntityIdentifiers = new HashMap<String, String>();
	@Override
	public void send(PKIMessage pkiMessage) {
		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(new GeneralPKIMessage(pkiMessage));
		verifyMessage(protectedPKIMessage);
		PKIHeader header = protectedPKIMessage.getHeader();
		ASN1OctetString recipKID = header.getRecipKID();
		CMPMessageEndpoint cmpMessageEndpoint = null;
		
		String recipientPublicKeyIdentifier = null;
		String recipientEmail = null;
		if(recipKID!=null){		
			recipientPublicKeyIdentifier = KeyIdUtils.hexEncode(recipKID.getOctets());
			cmpMessageEndpoint = publicKeyIdentifier2EndPoint.get(recipientPublicKeyIdentifier);
			if(cmpMessageEndpoint==null)
				throw new IllegalArgumentException("Recipient with public key id : " +recipientPublicKeyIdentifier+ " not found");
		} else {
			GeneralName recipient = header.getRecipient();
			if(recipient.getTagNo()==GeneralName.rfc822Name){
				DERIA5String emailString = DERIA5String.getInstance(recipient.getName());
				recipientEmail = emailString.getString();
			} else if (recipient.getTagNo()==GeneralName.directoryName){
				X500Name recipientDN = X500Name.getInstance(recipient.getName());
				String emailFromDN = X500NameHelper.readEmailFromDN(recipientDN);
				recipientEmail = emailFromDN;
			} else {
				throw new IllegalArgumentException("Expecting recipient to be from type rfc822Name or directoryName");
			}
			if(recipientEmail==null)
				throw new IllegalArgumentException("Request must specify either the recipient public key id or the recipient email int the recipient field in form of an rfc822Name or a directoryName");

			String endEntityIdentifier = email2EndEntityIdentifiers.get(recipientEmail);
			if(endEntityIdentifier==null)
				throw new IllegalArgumentException("No end entity registered with email: " + recipientEmail);
			
			Set<Entry<String,String>> entrySet = publicKeyId2ntityIdentifiers.entrySet();
			for (Entry<String, String> entry : entrySet) {
				if(endEntityIdentifier.equals(entry.getValue())){
					recipientPublicKeyIdentifier=entry.getKey();
				}
			}
			if(recipientPublicKeyIdentifier==null)
				throw new IllegalStateException("No recipient could be found for recipient with email: " + recipientEmail + " with endEntityIdentifier " + endEntityIdentifier);
			cmpMessageEndpoint = publicKeyIdentifier2EndPoint.get(recipientPublicKeyIdentifier);
			if(cmpMessageEndpoint==null)
				throw new IllegalStateException("No recipient could be found for recipient with email: " + recipientEmail + 
						" with endEntityIdentifier " + endEntityIdentifier +
						" with recipientPublicKeyIdentifier " +recipientPublicKeyIdentifier);
		}

		cmpMessageEndpoint.receive(pkiMessage);
	}

	@Override
	public void registerMessageEndPoint(CMPMessageEndpoint endpoint,
			PKIMessage initRequest) 
	{
		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(new GeneralPKIMessage(initRequest));
		verifyMessage(protectedPKIMessage);

		X509CertificateHolder[] certificates = protectedPKIMessage.getCertificates();
		if(certificates.length<1)
			throw new IllegalStateException("No certificate sent with registration request.");
		
		X509CertificateHolder subjectCertificate = certificates[0];
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(subjectCertificate);
		if(publicKeyIdentifier2EndPoint.containsKey(publicKeyIdentifier))
			throw new IllegalStateException("Sender with key id exists");
		
		List<String> subjectEmails = X500NameHelper.readSubjectEmails(subjectCertificate);
		String endEntityIdentifier = X500NameHelper.readSubjectUniqueIdentifier(subjectCertificate);
		
		for (String email : subjectEmails) {
			String existingUniqueId = email2EndEntityIdentifiers.get(email);
			if(existingUniqueId!=null && !existingUniqueId.equals(endEntityIdentifier))
				throw new IllegalStateException("Email in possession of another subject");
		}
		for (String email : subjectEmails) {
			if(!email2EndEntityIdentifiers.containsKey(email)){
				email2EndEntityIdentifiers.put(email, endEntityIdentifier);
			}
		}
		
		publicKeyIdentifier2EndPoint.put(publicKeyIdentifier, endpoint);
		
		publicKeyId2ntityIdentifiers.put(publicKeyIdentifier, endEntityIdentifier);
	}

	private void verifyMessage(ProtectedPKIMessage protectedPKIMessage) {
		// TODO Auto-generated method stub
		
	}

}
