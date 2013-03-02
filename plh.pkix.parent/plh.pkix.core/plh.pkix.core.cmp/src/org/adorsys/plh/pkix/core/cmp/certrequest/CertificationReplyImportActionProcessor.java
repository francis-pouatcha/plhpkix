package org.adorsys.plh.pkix.core.cmp.certrequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.adorsys.plh.pkix.core.cmp.message.CertificateChain;
import org.adorsys.plh.pkix.core.cmp.message.CertificateChainActionData;
import org.adorsys.plh.pkix.core.cmp.stores.PendingCertAnnouncements;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.Action;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionHandler;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;

public class CertificationReplyImportActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(CertificationReplyImportActionProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		CertificateChainActionData actionData = actionContext.get(CertificateChainActionData.class,null);
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class,null);
		PendingCertAnnouncements pendingCertAnns = actionContext.get(PendingCertAnnouncements.class,null);
		
		checker.checkNull(actionData,keyStoreWraper,pendingCertAnns);
		
		// Import the certificate into key store
		CertificateChain certificateChain = actionData.getCertificateChain();
		ProcessingResults<List<X509CertificateHolder>> processingResults = new ProcessingResults<List<X509CertificateHolder>>();
		Certificate[] certArray = certificateChain.toCertArray();
		try {
			keyStoreWraper.importIssuedCertificate(certArray);
		} catch (PlhCheckedException e) {
			processingResults.addError(e.getErrorMessage());
		}
		List<X509CertificateHolder> returnValue = new ArrayList<X509CertificateHolder>(certArray.length);
		for (Certificate certificate : certArray) {
			returnValue.add(new X509CertificateHolder(certificate));
		}
		processingResults.setReturnValue(returnValue);
		Action postAction = new CertificationReplyImportPostAction(actionContext, processingResults);
		ActionHandler actionHandler = actionContext.get(ActionHandler.class);
		actionHandler.handle(Arrays.asList(postAction));
	}
}
