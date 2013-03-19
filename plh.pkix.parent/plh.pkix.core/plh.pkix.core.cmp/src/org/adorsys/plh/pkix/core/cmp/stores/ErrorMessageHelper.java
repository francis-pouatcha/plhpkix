package org.adorsys.plh.pkix.core.cmp.stores;

import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingStatus;
import org.bouncycastle.i18n.ErrorBundle;

public class ErrorMessageHelper {

	public static void processError(CMPRequest request, 
			CMPRequests requests, ErrorBundle errorMessage){
		request.addStatus(ASN1ProcessingStatus.error);
		ProcessingResults<Void> processingResults = new ProcessingResults<Void>();
		processingResults.addError(errorMessage);
		ASN1ProcessingResult asn1ProcessingResult = processingResults.getASN1ProcessingResult();
		request.addProcessingResult(asn1ProcessingResult);
		requests.storeRequest(request);
	}
}
