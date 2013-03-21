package org.adorsys.plh.pkix.core.cmp.message;

import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.jca.PKIXParametersFactory;
import org.adorsys.plh.pkix.core.utils.store.PKISignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/**
 * First check the message for conformity. In case of a conformity error,
 * the message shall deleted.
 * 
 * If the message is sent back to the user, a copy should be held  for future 
 * processing. If the same message is repeated with a conformity error, the 
 * message is simply marked for deletion. The means resent occurs only one time
 * per thread. A thread is identified with the transaction id.s
 * 
 * @author francis
 *
 */
public class PkiMessageChecker {
	
	private static final String RESOURCE_NAME = CMPMessageValidatorMessages.class.getName();
	
	private final BuilderChecker checker = new BuilderChecker(PkiMessageChecker.class);
	public PKISignedMessageValidator check(
			PKIMessage pkiMessage, ContactManager contactManager){
		checker.checkNull(contactManager,pkiMessage);
		
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(pkiMessage);		
		PKIHeader pkiHeader = generalPKIMessage.getHeader();

		if(!generalPKIMessage.hasProtection())
			throw PlhUncheckedException.toException(RESOURCE_NAME,
			CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_missingProtection);
		
		GeneralName sender = pkiHeader.getSender();
		if (sender == null){
			throw PlhUncheckedException.toException(RESOURCE_NAME,
				CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_missingSender);
		} else if(sender.getTagNo()!=GeneralName.directoryName){
			throw PlhUncheckedException.toException(RESOURCE_NAME,
				CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_senderNotADirectoryName);
		}

		GeneralName recipient = pkiHeader.getRecipient();
		if (recipient == null)
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_missingRecipient);

		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(generalPKIMessage);

		if (protectedPKIMessage.hasPasswordBasedMacProtection())
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_macProtectionNotSupported);
		
		X509CertificateHolder[] certificates = protectedPKIMessage.getCertificates();
		if(certificates==null || certificates.length<1)
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_notCertificateSentWithMessage);

		// first certificate if in chain must be for the sender
		X509CertificateHolder senderCertificate = certificates[0];
		X500Name subjectDN = X500NameHelper.readSubjectDN(senderCertificate);
		X500Name senderX500Name = X500Name.getInstance(sender.getName());
		if(!senderX500Name.equals(subjectDN))
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_senderNotMatchingCertificate,
					new Object[]{senderX500Name,senderCertificate.getSubject()});
		
		Date signingTime = null;
		DERGeneralizedTime messageTime = protectedPKIMessage.getHeader().getMessageTime();
		if(messageTime!=null){
			try {
				signingTime = messageTime.getDate();
			} catch (ParseException e) {
				throw PlhUncheckedException.toException(RESOURCE_NAME,
						CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_canNotParseMessageTime,
						e, PkiMessageChecker.class);
			}
		} else {
			throw PlhUncheckedException.toException(RESOURCE_NAME,
					CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_missingMessageTime,
					new Object[]{senderX500Name,senderCertificate.getSubject()});
		}
		
		try {
			ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().build(senderCertificate);
			if(!protectedPKIMessage.verify(contentVerifierProvider))
				throw PlhUncheckedException.toException(RESOURCE_NAME,
						CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_signatureNotValid,
						new Object[]{senderX500Name,senderCertificate.getSubject()});
		} catch (OperatorCreationException e) {
			throw PlhUncheckedException.toException(e, PkiMessageChecker.class);
		} catch (CertificateException e) {
			throw PlhUncheckedException.toException(e, PkiMessageChecker.class);
		} catch (CMPException e) {
			throw PlhUncheckedException.toException(e, PkiMessageChecker.class);
		}

		PKIXParameters params = PKIXParametersFactory.makeParams(
				contactManager.getTrustAnchors(),
				contactManager.getCrl(),
				contactManager.findCertStores(certificates));

		// Validate certificate.
		List<X509CertificateHolder> signerX509CertificateHolders = Arrays.asList(senderCertificate);
		
		return new PKISignedMessageValidator()
			.withCerts(V3CertificateUtils.createCertStore(certificates))
			.withPKIXParameters(params)
			.withSignerCertificates(signerX509CertificateHolders)
			.validate(signingTime);
	}
}
