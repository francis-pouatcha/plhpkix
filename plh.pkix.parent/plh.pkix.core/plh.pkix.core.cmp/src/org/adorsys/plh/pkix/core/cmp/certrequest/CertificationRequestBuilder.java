package org.adorsys.plh.pkix.core.cmp.certrequest;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.stores.PendingRequest;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequestData;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequests;
import org.adorsys.plh.pkix.core.cmp.utils.CertTemplateExtensionBuilder;
import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Builds an initial certification request. The subject's environment generates a 
 * key pair, generates a self signed certificate and envelopes it into a 
 * certification request that is sent to the intended certification authority.
 * 
 * @author francis
 *
 */
public class CertificationRequestBuilder {

	private PendingRequests pendingRequests;
	// the cert template. This is either the self signed certificate or
	// A certificate issued by another authority.
    private X509CertificateHolder subjectPreCertificate;
    private X500Name certAuthorityName;

	private boolean ca;
	private int keyUsage=-1;
	private boolean keyUsageSet = false;
	private GeneralNames subjectAltName;

	private final BuilderChecker checker = new BuilderChecker(CertificationRequestBuilder.class);
    public PendingRequestData build(PrivateKey subjectPrivateKey) throws NoSuchAlgorithmException, OperatorCreationException, CMPException{
    	checker.checkDirty()
    		.checkNull(subjectPrivateKey,subjectPreCertificate,certAuthorityName);


		ContentSigner subjectSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption")
			.setProvider(ProviderUtils.bcProvider)
			.build(subjectPrivateKey );
        
        // The initialization request must specify the SubjectPublicKeyInfo, The keyId and the validity
        // of each certificate requested.
        Date notBefore = new Date();
        Date notAfter = DateUtils.addYears(notBefore, 10);
		OptionalValidity optionalValidity = new OptionalValidityHolder(notBefore,notAfter).getOptionalValidity();

		CertTemplateExtensionBuilder extBuilder = new CertTemplateExtensionBuilder()
			.withCa(ca);
		if(subjectAltName!=null)
			extBuilder = extBuilder.withSubjectAltName(subjectAltName);
		if(keyUsageSet)
			extBuilder = extBuilder.withKeyUsage(keyUsage);
			
		
		CertTemplate certTemplate = new CertTemplateBuilder()
        	.setSubject(subjectPreCertificate.getSubject())
        	.setIssuer(certAuthorityName)
        	.setPublicKey(subjectPreCertificate.getSubjectPublicKeyInfo())
        	.setValidity(optionalValidity)
        	.setExtensions(extBuilder.build())
        	.build();
		
		byte[] txId = UUIDUtils.newUUIDAsBytes();
		ASN1Integer certReqId = new ASN1Integer(new BigInteger(txId));
		Controls controls = null;
		CertRequest certRequest = new CertRequest(certReqId, certTemplate, controls);
		CertReqMsg certReqMsg = new CertReqMsg(certRequest, null, null);
        CertReqMessages certReqMessages = new CertReqMessages(new CertReqMsg[]{certReqMsg});
        GeneralName subjectGeneralName = new GeneralName(subjectPreCertificate.getSubject());
        GeneralName caGeneralName = new GeneralName(certAuthorityName);
        byte[] subjectKeyId = KeyIdUtils.readSubjectKeyIdentifierAsByteString(subjectPreCertificate);
        ProtectedPKIMessage mainMessage = new ProtectedPKIMessageBuilder(subjectGeneralName, caGeneralName)
                                                  .setBody(new PKIBody(PKIBody.TYPE_CERT_REQ, certReqMessages))
                                                  .addCMPCertificate(subjectPreCertificate)// certificate used to sign the message
                                                  .setMessageTime(new Date())
                                                  .setSenderKID(subjectKeyId)
											      .setSenderNonce(UUIDUtils.newUUIDAsBytes())
											      .setTransactionID(txId)
                                                  .build(subjectSigner);
		PKIMessage pkiMessage = mainMessage.toASN1Structure();
		
		PendingRequest pendingRequest = new PendingRequest(certReqId, pkiMessage, null);
		PendingRequestData pendingRequestData = new PendingRequestData(pendingRequest);
		pendingRequests.storePollRequestHolder(certReqId.getPositiveValue(), pendingRequestData);
		return pendingRequestData;
//		PendingRequests pendingRequests = actionContext.get(PendingRequests.class, null);
//		actionContext.put(PendingRequestData.class, null, pendingRequestData);
	}
	public CertificationRequestBuilder withCa(boolean ca) {
		this.ca = ca;
		return this;
	}

	public CertificationRequestBuilder withKeyUsage(int keyUsage) {
		if(keyUsageSet){
			this.keyUsage=this.keyUsage|keyUsage;
		} else {
			this.keyUsage=keyUsage;
			keyUsageSet=true;
		}
		return this;
	}

	public CertificationRequestBuilder withSubjectAltName(GeneralNames subjectAltName) {
		this.subjectAltName = subjectAltName;
		return this;
	}

	public CertificationRequestBuilder withCertAuthorityName(X500Name certAuthorityName) {
		this.certAuthorityName = certAuthorityName;
		return this;
	}

	public CertificationRequestBuilder withSubjectCert(X509CertificateHolder subjectCert) {
		this.subjectPreCertificate = subjectCert;
		return this;
	}
	public CertificationRequestBuilder withPendingRequests(PendingRequests pendingRequests) {
		this.pendingRequests = pendingRequests;
		return this;
	}
	
}
