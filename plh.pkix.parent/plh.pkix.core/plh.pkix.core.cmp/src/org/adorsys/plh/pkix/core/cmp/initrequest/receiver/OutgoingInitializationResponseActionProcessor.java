package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequest;
import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.smime.contact.ContactManagerImpl;
import org.adorsys.plh.pkix.core.smime.store.KeyAndContactDB;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyEntryAndCertificate;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.jcajce.JcaEncryptedValueBuilder;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;

public class OutgoingInitializationResponseActionProcessor implements ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(OutgoingInitializationResponseActionProcessor.class);
	@Override
	public void process(ActionContext context) {
		IncomingInitializationRequestData requestData = context.get(IncomingInitializationRequestData.class);
		KeyStoreWraper keyStoreWraper = context.get(KeyStoreWraper.class);
		ContactManager contactManager = context.get(ContactManagerImpl.class);
		ActionHandler actionHandler = context.get(ActionHandler.class);
		checker.checkNull(requestData, keyStoreWraper, actionHandler);
		
		IncomingRequest incomingRequest = requestData.getIncomingRequest();
		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(new GeneralPKIMessage(incomingRequest.getPkiMessage()));
		PKIBody pkiBody = protectedPKIMessage.getBody();
		
		CertReqMessages certReqMessages = CertReqMessages.getInstance(pkiBody
				.getContent());
		CertReqMsg[] certReqMsgArray = certReqMessages.toCertReqMsgArray();
		List<CertResponse> certResponses = new ArrayList<CertResponse>();
		
		for (CertReqMsg certReqMsg : certReqMsgArray) {
			CertRequest certReq = certReqMsg.getCertReq();
			CertTemplate certTemplate = certReq.getCertTemplate();

			KeyAndContactDB db = new KeyAndContactDB(keyStoreWraper, contactManager);
			
			List<KeyEntryAndCertificate> foundEntries = null;
			
			// we start searching with the public key
			foundEntries = db.findContacts(certTemplate.getPublicKey());

			// then the subject key identifier
			if(foundEntries==null || foundEntries.isEmpty())
				foundEntries = db.findContacts(KeyIdUtils.readSubjectKeyIdentifier(certTemplate));

			// We try with the subject of certificate read
			// either from the subject field or from the subjectAltNameField
			if(foundEntries==null || foundEntries.isEmpty())
				foundEntries = db.findContacts(X500NameHelper.readSubjectDN(certTemplate));

			// try with subject unique identifier. Proprietary
			if(foundEntries==null || foundEntries.isEmpty())
				foundEntries = db.findContacts(certTemplate.getSubjectUID());
			
			// lets try with the subject email if the DN does not produce
			// any result.
			if(foundEntries==null || foundEntries.isEmpty())
				foundEntries = db.findContacts(X500NameHelper.readSubjectEmails(certTemplate));
			
			if(foundEntries==null || foundEntries.isEmpty()) continue;
			
			foundEntries = filterContacts(foundEntries, certTemplate.getValidity());

			foundEntries = filterContacts(foundEntries, KeyIdUtils.readAuthorityKeyIdentifier(certTemplate));

			foundEntries = filterContacts(foundEntries, certTemplate.getIssuerUID());
			
			foundEntries = filterContactsByIssuer(foundEntries, certTemplate.getIssuer());
			
			foundEntries = filterContactsByIssuerEmails(foundEntries, X500NameHelper.readIssuerEmails(certTemplate));

			X509CertificateHolder[] certificates = protectedPKIMessage.getCertificates();
			X509CertificateHolder senderCertificate = certificates[0];
			JceAsymmetricKeyWrapper jceAsymmetricKeyWrapper = new JceAsymmetricKeyWrapper(V3CertificateUtils.extractPublicKey(senderCertificate));
			OutputEncryptor encryptor;
			try {
			    encryptor = new JceCRMFEncryptorBuilder(PKCSObjectIdentifiers.des_EDE3_CBC).setProvider(ProviderUtils.bcProvider).build();
			} catch (CRMFException e) {
			    throw new IllegalStateException(e);
			}
			for (KeyEntryAndCertificate foundEntry : foundEntries) {
				List<X509CertificateHolder> chain = foundEntry.getCertificateChain();
				for (X509CertificateHolder returningCertificate : chain) {
					JcaEncryptedValueBuilder jcaEncryptedValueBuilder = new JcaEncryptedValueBuilder(jceAsymmetricKeyWrapper, encryptor);
					EncryptedValue encryptedCert;
					try {
						encryptedCert = jcaEncryptedValueBuilder.build(returningCertificate);
					} catch (CRMFException e) {
						throw new IllegalStateException(e);
					}
					
					CertOrEncCert certOrEncCert = new CertOrEncCert(encryptedCert);
					CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(certOrEncCert);
					PKIStatusInfo status = new PKIStatusInfo(PKIStatus.granted);
					ASN1OctetString rspInfo = null;
					CertResponse certResponse = new CertResponse(certReq.getCertReqId(), status, 
							certifiedKeyPair, rspInfo);
					certResponses.add(certResponse);
				}
			}
		}
		
		CMPCertificate[] caPubs = null;
		CertResponse[] response = certResponses.toArray(new CertResponse[certResponses.size()]);
		CertRepMessage certRepMessage = new CertRepMessage(caPubs, response);
		
		PKIHeader header = protectedPKIMessage.getHeader();
		GeneralName certificateRecipient = header.getSender();
		ASN1OctetString myPublicKeyIdentifier = header.getRecipKID();
		PrivateKeyEntry messageKeyEntry = null;
		if(myPublicKeyIdentifier!=null){
			messageKeyEntry = keyStoreWraper.findPrivateKeyEntryByPublicKeyIdentifier(myPublicKeyIdentifier.getOctets());
		}
		if(messageKeyEntry==null){
			GeneralName me = header.getRecipient();
			// if the recipient was a simple email address, get any keypair carrying the email address.
			if(me.getTagNo()==GeneralName.rfc822Name){
				String myEmail = DERIA5String.getInstance(me.getName()).getString();
				messageKeyEntry = keyStoreWraper.findMessagePrivateKeyEntryByEmail(myEmail);
			} else if (me.getTagNo()==GeneralName.directoryName){
				X500Name myDN = X500Name.getInstance(me.getName());
				messageKeyEntry = keyStoreWraper.findMessagePrivateKeyEntryBySubject(myDN);
				if(messageKeyEntry==null){
					String myEmail = X500NameHelper.readEmailFromDN(myDN);
					messageKeyEntry = keyStoreWraper.findMessagePrivateKeyEntryByEmail(myEmail);					
				}
			}
			if(messageKeyEntry==null){
				messageKeyEntry = keyStoreWraper.findAnyMessagePrivateKeyEntry();
			}
		}
		
		Certificate myCertificate = messageKeyEntry.getCertificate();
		X509CertificateHolder myCertificateHolder = V3CertificateUtils.getX509CertificateHolder(myCertificate);
		ProtectedPKIMessage mainMessage;
		byte[] senderKeyID = KeyIdUtils.createPublicKeyIdentifierAsByteString(myCertificateHolder);
		ProtectedPKIMessageBuilder protectedPKIMessageBuilder = 
				new ProtectedPKIMessageBuilder(new GeneralName(myCertificateHolder.getSubject()), certificateRecipient)
				.setBody(new PKIBody(PKIBody.TYPE_INIT_REP, certRepMessage))
				.addCMPCertificate(myCertificateHolder)
				.setMessageTime(new Date())
				.setSenderKID(senderKeyID)
				.setRecipKID(header.getSenderKID().getOctets())
				.setRecipNonce(header.getSenderNonce().getOctets())
				.setSenderNonce(UUIDUtils.newUUIDAsBytes())
				.setTransactionID(header.getTransactionID().getOctets());
		
		ContentSigner senderSigner = V3CertificateUtils.getContentSigner(messageKeyEntry.getPrivateKey(), "MD5WithRSAEncryption");

		try {
			mainMessage = protectedPKIMessageBuilder.build(senderSigner);
		} catch (CMPException e) {
			throw new IllegalStateException(e);
		}
		PKIMessage responseMessage = mainMessage.toASN1Structure();
		incomingRequest.setResponseMessage(responseMessage);

		ProcessingResults<IncomingInitializationRequestData> processingResults = new ProcessingResults<IncomingInitializationRequestData>();
		processingResults.setReturnValue(requestData);
		
		OutgoingInitializationResponsePostAction postAction = 
					new OutgoingInitializationResponsePostAction(context, processingResults);
		List<Action> actions = new ArrayList<Action>();
		actions.add(postAction);
		actionHandler.handle(actions);
	}

	private List<KeyEntryAndCertificate> filterContacts(
			List<KeyEntryAndCertificate> foundCertificates,
			OptionalValidity optionalValidity) {
		if(optionalValidity==null) return foundCertificates;
		List<KeyEntryAndCertificate> result =new ArrayList<KeyEntryAndCertificate>();
		OptionalValidityHolder validityHolder = new OptionalValidityHolder(optionalValidity);
		for (KeyEntryAndCertificate entry : foundCertificates) {
			if(V3CertificateUtils.isValid(entry.getCertHolder(), validityHolder.getNotBeforeAsDate(), validityHolder.getNotAfterAsDate()))
				result.add(entry);
		}
		return result;
	}

	private List<KeyEntryAndCertificate> filterContactsByIssuerEmails(
			List<KeyEntryAndCertificate> foundCertificates,
			List<String> issuerEmails) {
		if(issuerEmails==null || issuerEmails.isEmpty()) return foundCertificates;
		
		List<KeyEntryAndCertificate> result = new ArrayList<KeyEntryAndCertificate>();
		for (KeyEntryAndCertificate entry : foundCertificates) {
			List<String> readIssuerEmails = X500NameHelper.readIssuerEmails(entry.getCertHolder());
			for (String issuerEmail : issuerEmails) {
				if(readIssuerEmails.contains(issuerEmail)){
					result.add(entry);
					break;
				}
			}
		}
		return result;
	}

	private List<KeyEntryAndCertificate> filterContactsByIssuer(
			List<KeyEntryAndCertificate> foundCertificates, X500Name issuer) {
		if(issuer==null) return foundCertificates;

		List<KeyEntryAndCertificate> result = new ArrayList<KeyEntryAndCertificate>();
		for (KeyEntryAndCertificate entry : foundCertificates) {
			if(issuer.equals(entry.getCertHolder().getIssuer()))result.add(entry);
		}
		return result;
	}

	private List<KeyEntryAndCertificate> filterContacts(
			List<KeyEntryAndCertificate> foundCertificates,
			DERBitString issuerUID) {
		if (issuerUID==null) return foundCertificates;
		byte[] issuerUIDBytes = issuerUID.getBytes();
		List<KeyEntryAndCertificate> result = new ArrayList<KeyEntryAndCertificate>();
		for (KeyEntryAndCertificate entry : foundCertificates) {
			byte[] createdPublicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsByteString(entry.getCertHolder());
			if(Arrays.equals(createdPublicKeyIdentifier, issuerUIDBytes))
				result.add(entry);
		}
		return result;
	}

	private List<KeyEntryAndCertificate> filterContacts(
			List<KeyEntryAndCertificate> foundCertificates,
			AuthorityKeyIdentifier authorityKeyIdentifier) {
		if(authorityKeyIdentifier==null) return foundCertificates;
		List<KeyEntryAndCertificate> result = new ArrayList<KeyEntryAndCertificate>();
		byte[] searchInput = KeyIdUtils.readAuthorityKeyIdentifierAsByteString(authorityKeyIdentifier);
		for (KeyEntryAndCertificate entry : foundCertificates) {
			byte[] asByteString = KeyIdUtils.readAuthorityKeyIdentifierAsByteString(entry.getCertHolder());
			if(Arrays.equals(searchInput, asByteString))
				result.add(entry);
		}
		return result;
	}
}
