package org.adorsys.plh.pkix.core.cmp.initrequest;

import org.adorsys.plh.pkix.core.cmp.message.CertificateChain;
import org.adorsys.plh.pkix.core.cmp.message.CertificateChainActionData;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.x509.Certificate;

public class InitializationResponseImportActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(InitializationResponseImportActionProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		CertificateChainActionData actionData = actionContext.get(CertificateChainActionData.class,null);
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class,null);
		
		checker.checkNull(actionData,keyStoreWraper);
		
		// Import the certificate into key store
		CertificateChain certificateChain = actionData.getCertificateChain();
		Certificate[] certArray = certificateChain.toCertArray();
		keyStoreWraper.importCertificates(certArray);
	}
}
