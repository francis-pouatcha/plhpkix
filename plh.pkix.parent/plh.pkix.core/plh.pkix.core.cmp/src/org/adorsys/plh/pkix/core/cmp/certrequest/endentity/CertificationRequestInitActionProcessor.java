package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Arrays;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * This processor assumes that user has selected the model certificate included in the
 * {@link CertificationRequestInitActionProcessor#REQUESTFIELDHOLDER} and the 
 * name of the certifying ca {@link CertificationRequestInitActionProcessor#CERTAUTHORITYNAME}
 * @author francis
 *
 */
public class CertificationRequestInitActionProcessor implements ActionProcessor {

	/**
	 * Keys for the context local to this processor
	 */
	public static final String REQUESTFIELDHOLDER="requestFieldHolder";
	public static final String CERTAUTHORITYNAME="certAuthorityName";
	
	private final BuilderChecker checker = new BuilderChecker(CertificationRequestInitActionProcessor.class);
	@Override
	public void process(ActionContext context) {
		CertificationRequestFieldHolder requestFieldHolder = context.get(CertificationRequestFieldHolder.class, REQUESTFIELDHOLDER);
		OutgoingCertificationRequests certificationRequests = context.get(OutgoingCertificationRequests.class);
		X500Name certAuthorityName = context.get(X500Name.class, CERTAUTHORITYNAME);
		KeyStoreWraper keyStoreWraper = context.get(KeyStoreWraper.class);
		PrivateKeyEntry privateKeyEntry = keyStoreWraper.findPrivateKeyEntry(requestFieldHolder.getSubjectPreCertificate());
		ActionHandler actionHandler = context.get(ActionHandler.class);
		checker.checkDirty().checkNull(requestFieldHolder, certAuthorityName,privateKeyEntry, actionHandler);
		
		CertificationRequestInitActionExecutor builder = new CertificationRequestInitActionExecutor()
			.withCertAuthorityName(certAuthorityName)
			.withNotAfter(requestFieldHolder.getNotAfter())
			.withNotBefore(requestFieldHolder.getNotBefore())
			.withSubjectAltNames(requestFieldHolder.getSubjectAltNames())
			.withSubjectDN(requestFieldHolder.getSubjectDN())
			.withSubjectOnlyInAlternativeName(requestFieldHolder.isSubjectOnlyInAlternativeName())
			.withSubjectPreCertificate(requestFieldHolder.getSubjectPreCertificate());
		if(requestFieldHolder.isCaSet())
			builder = builder.withCa(requestFieldHolder.isCa());
		if(requestFieldHolder.isKeyUsageSet())
			builder = builder.withKeyUsage(requestFieldHolder.getKeyUsage());

		ProcessingResults<OutgoingCertificationRequestData> processingResults = builder.build(privateKeyEntry.getPrivateKey());
		OutgoingCertificationRequestData certificationRequestData = processingResults.getReturnValue();
		OutgoingCertificationRequest certificationRequest = certificationRequestData.getOutgoingCertificationRequest();
		certificationRequests.storeCertificationRequest(certificationRequest.getCertReqId().getPositiveValue(), certificationRequestData);
		Action postAction = new CertificationRequestInitPostAction(context, processingResults);
		actionHandler.handle(Arrays.asList(postAction));
	}
}
