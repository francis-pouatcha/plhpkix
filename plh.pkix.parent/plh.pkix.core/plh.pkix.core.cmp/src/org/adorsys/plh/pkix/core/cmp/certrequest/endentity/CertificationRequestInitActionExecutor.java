package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.certrequest.CertRequestMessages;
import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedException;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
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
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.operator.ContentSigner;

/**
 * Builds an initial certification request. The subject's environment generates a 
 * key pair, generates a self signed certificate and envelopes it into a 
 * certification request that is sent to the intended certification authority.
 * 
 * @author francis
 *
 */
public class CertificationRequestInitActionExecutor {

	private boolean ca;
	private boolean caSet;

	private X500Name subjectDN;
	
	private boolean subjectOnlyInAlternativeName;

	private SubjectPublicKeyInfo subjectPublicKeyInfo;

	private Date notBefore;

	private Date notAfter;

	private int keyUsage=-1;
	private boolean keyUsageSet = false;

	private GeneralNames subjectAltNames;

    private X500Name certAuthorityName;
	
	// the cert template. This is either the self signed certificate or
	// A certificate issued by another authority.
    private X509CertificateHolder subjectPreCertificate;

	private final BuilderChecker checker = new BuilderChecker(CertificationRequestInitActionExecutor.class);
    public ProcessingResults<OutgoingCertificationRequestData> build(PrivateKey subjectPrivateKey) {
    	checker.checkDirty()
    		.checkNull(subjectPrivateKey,subjectPreCertificate,certAuthorityName);

    	ProcessingResults<OutgoingCertificationRequestData> processingResults = new ProcessingResults<OutgoingCertificationRequestData>();
    	
		if(subjectPublicKeyInfo==null) subjectPublicKeyInfo=subjectPreCertificate.getSubjectPublicKeyInfo();
		if(subjectDN==null) subjectDN=subjectPreCertificate.getSubject();
		if(notBefore==null) notBefore=subjectPreCertificate.getNotBefore();
		if(notAfter==null) notAfter=subjectPreCertificate.getNotAfter();
		
		if(!keyUsageSet)copyKeyUsage(subjectPreCertificate);
		
		if(subjectAltNames==null){
			Extension extension = subjectPreCertificate.getExtension(X509Extension.subjectAlternativeName);
			if(extension!=null) subjectAltNames = GeneralNames.getInstance(extension.getParsedValue());
		}
		
		if(!caSet){
			Extension basicConstraintsExtension = subjectPreCertificate.getExtension(X509Extension.basicConstraints);
			BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
			withCa(basicConstraints.isCA());
		}

		OptionalValidity optionalValidity = new OptionalValidityHolder(notBefore,notAfter).getOptionalValidity();

		BasicConstraints basicConstraints = null;
		if(ca){
			// self signed ca certificate
			basicConstraints = new BasicConstraints(true);
			subjectOnlyInAlternativeName = false;// in ca case, subject must subject must be set
		} else {
			basicConstraints = new BasicConstraints(false);
		}
		
		
		ExtensionsGenerator extGenerator = new ExtensionsGenerator();
		try {
			extGenerator.addExtension(X509Extension.basicConstraints,true, basicConstraints);
			
			if(keyUsageSet){
				extGenerator.addExtension(X509Extension.keyUsage,
						true, new KeyUsage(this.keyUsage));
			}
			// complex rules for subject alternative name. See rfc5280
			if(subjectAltNames!=null){
				if(subjectOnlyInAlternativeName){
					extGenerator.addExtension(X509Extension.subjectAlternativeName, true, subjectAltNames);
				} else {
					extGenerator.addExtension(X509Extension.subjectAlternativeName, false, subjectAltNames);
				}
			}
		} catch(IOException e){
            ErrorBundle msg = new ErrorBundle(CertRequestMessages.class.getName(),
            		CertRequestMessages.CertRequestMessages_generate_errorBuildingExtention,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
				
		CertTemplate certTemplate = new CertTemplateBuilder()
        	.setSubject(subjectDN)
        	.setIssuer(certAuthorityName)
        	.setPublicKey(subjectPublicKeyInfo)
        	.setValidity(optionalValidity)
        	.setExtensions(extGenerator.generate())
        	.build();
		
		byte[] txId = UUIDUtils.newUUIDAsBytes();
		ASN1Integer certReqId = new ASN1Integer(new BigInteger(txId));
		Controls controls = null;
		CertRequest certRequest = new CertRequest(certReqId, certTemplate, controls);
		CertReqMsg certReqMsg = new CertReqMsg(certRequest, null, null);
        CertReqMessages certReqMessages = new CertReqMessages(new CertReqMsg[]{certReqMsg});
        // read subject dn from the precertificate. The original one might be null
        GeneralName subjectGeneralName = new GeneralName(X500NameHelper.readSubjectDN(subjectPreCertificate));
        GeneralName caGeneralName = new GeneralName(certAuthorityName);
        byte[] subjectKeyId = KeyIdUtils.readSubjectKeyIdentifierAsByteString(subjectPreCertificate);
		ContentSigner subjectSigner = V3CertificateUtils.getContentSigner(subjectPrivateKey, "MD5WithRSAEncryption");

		ProtectedPKIMessage mainMessage;
		try {
			mainMessage = new ProtectedPKIMessageBuilder(subjectGeneralName, caGeneralName)
			                                          .setBody(new PKIBody(PKIBody.TYPE_CERT_REQ, certReqMessages))
			                                          .addCMPCertificate(subjectPreCertificate)// certificate used to sign the message
			                                          .setMessageTime(new Date())
			                                          .setSenderKID(subjectKeyId)
												      .setSenderNonce(UUIDUtils.newUUIDAsBytes())
												      .setTransactionID(txId)
			                                          .build(subjectSigner);
		} catch (CMPException e) {
            ErrorBundle msg = new ErrorBundle(CertRequestMessages.class.getName(),
            		CertRequestMessages.CertRequestMessages_generate_generalCMPException,
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new PlhUncheckedException(msg, e);
		}
		PKIMessage pkiMessage = mainMessage.toASN1Structure();
		OutgoingCertificationRequest certificationRequest = 
				new OutgoingCertificationRequest(certReqId, pkiMessage, new DERGeneralizedTime(new Date()));
		OutgoingCertificationRequestData certificationRequestData = new OutgoingCertificationRequestData(certificationRequest);
		processingResults.setReturnValue(certificationRequestData);
		return processingResults;
	}
	public CertificationRequestInitActionExecutor withCa(boolean ca) {
		this.ca = ca;
		this.caSet=true;
		return this;
	}

	public CertificationRequestInitActionExecutor withKeyUsage(int keyUsage) {
		if(keyUsageSet){
			this.keyUsage=this.keyUsage|keyUsage;
		} else {
			this.keyUsage=keyUsage;
			keyUsageSet=true;
		}
		return this;
	}

	public CertificationRequestInitActionExecutor withSubjectDN(X500Name subjectDN) {
		this.subjectDN = subjectDN;
		return this;
	}
	public CertificationRequestInitActionExecutor withSubjectOnlyInAlternativeName(boolean subjectOnlyInAlternativeName) {
		this.subjectOnlyInAlternativeName = subjectOnlyInAlternativeName;
		return this;
	}
	public CertificationRequestInitActionExecutor withSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
		this.subjectPublicKeyInfo = subjectPublicKeyInfo;
		return this;
	}
	public CertificationRequestInitActionExecutor withNotBefore(Date notBefore) {
		this.notBefore = notBefore;
		return this;
	}
	public CertificationRequestInitActionExecutor withNotAfter(Date notAfter) {
		this.notAfter = notAfter;
		return this;
	}

	public CertificationRequestInitActionExecutor withSubjectAltNames(GeneralNames subjectAltNames) {
		this.subjectAltNames = subjectAltNames;
		return this;
	}

	public CertificationRequestInitActionExecutor withSubjectPreCertificate(X509CertificateHolder subjectPreCertificate) {
		this.subjectPreCertificate = subjectPreCertificate;
		return this;
	}
	public CertificationRequestInitActionExecutor withCertAuthorityName(X500Name certAuthorityName) {
		this.certAuthorityName = certAuthorityName;
		return this;
	}
	
	private void copyKeyUsage(X509CertificateHolder issuerCertificate) {
		int ku = KeyUsageUtils.getKeyUsage(issuerCertificate);
		if(ku!=-1)withKeyUsage(ku);
	}
}
