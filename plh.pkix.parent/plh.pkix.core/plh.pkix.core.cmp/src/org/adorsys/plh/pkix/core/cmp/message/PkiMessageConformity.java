package org.adorsys.plh.pkix.core.cmp.message;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.i18n.ErrorBundle;

/**
 * Checks the PKIMessage for conformity. We require all messages to have:
 * - a sender
 * - a receiver
 * - a certificate based protection
 * 
 * @author francis
 * 
 */
public class PkiMessageConformity {
	
	private static final String RESOURCE_NAME = CMPMessageValidatorMessages.class.getName();

	private GeneralPKIMessage generalPKIMessage;
	
	private final BuilderChecker checker = new BuilderChecker(PkiMessageConformity.class);
	
	public ProcessingResults<ProtectedPKIMessage> check() {
		checker.checkDirty()
			.checkNull(generalPKIMessage);

		ProcessingResults<ProtectedPKIMessage> enb = new ProcessingResults<ProtectedPKIMessage>();
		PKIHeader pkiHeader = generalPKIMessage.getHeader();


		GeneralName sender = pkiHeader.getSender();
		if (sender == null){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_missingSender);
			throw new PlhUncheckedException(msg);
		} else if(sender.getTagNo()!=GeneralName.directoryName){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_senderNotADirectoryName);
			throw new PlhUncheckedException(msg);
		}

		GeneralName recipient = pkiHeader.getRecipient();
		if (recipient == null){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_missingRecipient);
			throw new PlhUncheckedException(msg);
		}

		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(generalPKIMessage);

		if (protectedPKIMessage.hasPasswordBasedMacProtection()){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					CMPMessageValidatorMessages.CMPMessageValidatorMessages_conformity_macProtectionNotSupported);
			throw new PlhUncheckedException(msg);
		}
		
		return enb;
	}

	public PkiMessageConformity withGeneralPKIMessage(GeneralPKIMessage generalPKIMessage) {
		this.generalPKIMessage = generalPKIMessage;
		return this;
	}
}
