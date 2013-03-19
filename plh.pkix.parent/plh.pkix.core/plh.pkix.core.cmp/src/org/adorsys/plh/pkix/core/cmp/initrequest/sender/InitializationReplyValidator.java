package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.security.cert.TrustAnchor;
import java.util.Set;

import org.adorsys.plh.pkix.core.cmp.certrequest.CertRequestMessages;
import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityComparator;
import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1CertValidationResult;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.i18n.ErrorBundle;

/**
 * Compare the cert template and the signed certificate and build a feedback 
 * request object for the user.
 * 
 * @author francis
 *
 */
public class InitializationReplyValidator {
	private static final String RESOURCE_NAME = CertRequestMessages.class.getName();

	private final BuilderChecker checker = new BuilderChecker(InitializationReplyValidator.class);

	private CertTemplate certTemplate;

	public void validate(final ASN1CertValidationResult certValidationResult, Set<TrustAnchor> trustAnchors){

		checker.checkDirty()
			.checkNull(certTemplate,certValidationResult, trustAnchors);
		
		Certificate certificate = certValidationResult.getCertificate();
		X509CertificateHolder requestedCertificate = new X509CertificateHolder(certificate);

		ProcessingResults<X509CertificateHolder> validationResult = new ProcessingResults<X509CertificateHolder>();
		validationResult.setReturnValue(requestedCertificate);
		
		checkIncludedSubject(validationResult);

		checkPublicKey(validationResult);
		
		checkIssuer(validationResult);
		
		checkValidity(validationResult);
	
		checkSerial(validationResult);

		checkExtensions(validationResult);
	}

	public InitializationReplyValidator withCertTemplate(CertTemplate certTemplate) {
		this.certTemplate = certTemplate;
		return this;
	}

	protected void checkExtensions(
			ProcessingResults<X509CertificateHolder> validationResult) {
		Extensions certTemplateExtensions = certTemplate.getExtensions();

		checkBasicConstraintExtension(certTemplateExtensions, validationResult);

		checkSubjectAlternativeNameExtension(certTemplateExtensions, validationResult);

		checkKeyUsageNameExtension(certTemplateExtensions, validationResult);

		checkAuthorityInfoAccessExtension(certTemplateExtensions, validationResult);
		
	}
	
	protected void checkAuthorityInfoAccessExtension(
			Extensions certTemplateExtensions,
			ProcessingResults<X509CertificateHolder> validationResult) {
		X509CertificateHolder requestedCertificate = validationResult.getReturnValue();
		Extension authorityInfoAccessExtension = certTemplateExtensions.getExtension(X509Extension.authorityInfoAccess);
		if(authorityInfoAccessExtension!=null){
			AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(authorityInfoAccessExtension.getParsedValue());
			Extension repAuthorityInfoAccessExtension = requestedCertificate.getExtension(X509Extension.authorityInfoAccess);
			AuthorityInformationAccess repAuthorityInformationAccess = null;
			if(repAuthorityInfoAccessExtension!=null){
				repAuthorityInformationAccess = AuthorityInformationAccess.getInstance(repAuthorityInfoAccessExtension.getParsedValue());
			}
			if(repAuthorityInformationAccess==null || !authorityInformationAccess.equals(repAuthorityInformationAccess)){
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"CertRequestMessages.certificate.authorityInfoAccessExtensionNoMatchingTemplate");
				validationResult.addNotification(msg);
			}
		}
	}

	protected void checkKeyUsageNameExtension(Extensions certTemplateExtensions,
			ProcessingResults<X509CertificateHolder> validationResult) {
		X509CertificateHolder requestedCertificate = validationResult.getReturnValue();
		int keyUsage = KeyUsageUtils.getKeyUsage(certTemplateExtensions);
		if(keyUsage>-1){
			int keyUsage2 = KeyUsageUtils.getKeyUsage(requestedCertificate);
			if(keyUsage!=keyUsage2){
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"CertRequestMessages.certificate.keyUsageExtensionNoMatchingTemplate");
				validationResult.addNotification(msg);
			}

		}
	}

	protected void checkSubjectAlternativeNameExtension(
			Extensions certTemplateExtensions,
			ProcessingResults<X509CertificateHolder> validationResult) {
		X509CertificateHolder requestedCertificate = validationResult.getReturnValue();
		Extension subjectAlternativeNameExtension = certTemplateExtensions.getExtension(X509Extension.subjectAlternativeName);
		if(subjectAlternativeNameExtension!=null) {
			GeneralNames subjectAltName = GeneralNames.getInstance(subjectAlternativeNameExtension.getParsedValue());
			Extension repSubjectAlternativeNameExtension = requestedCertificate.getExtension(X509Extension.subjectAlternativeName);
			GeneralNames repSubjectAlternativeName=null;
			if(repSubjectAlternativeNameExtension!=null){
				repSubjectAlternativeName = GeneralNames.getInstance(repSubjectAlternativeNameExtension.getParsedValue());
			}
			if(repSubjectAlternativeName==null || !subjectAltName.equals(repSubjectAlternativeName)){
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"CertRequestMessages.certificate.subjectAlternativeNameExtensionNoMatchingTemplate");
				validationResult.addNotification(msg);
			}
		}
	}

	protected void checkBasicConstraintExtension(
			Extensions certTemplateExtensions,
			ProcessingResults<X509CertificateHolder> validationResult){
		X509CertificateHolder requestedCertificate = validationResult.getReturnValue();
		Extension basicConstraintsExtension = certTemplateExtensions.getExtension(X509Extension.basicConstraints);
		BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
		if(basicConstraints!=null){
			Extension repBasicConstraintsExtension = requestedCertificate.getExtension(X509Extension.basicConstraints);
			BasicConstraints repBasicConstraints=null;
			if(repBasicConstraintsExtension!=null){
				repBasicConstraints = BasicConstraints.getInstance(repBasicConstraintsExtension.getParsedValue());
			}
			if(repBasicConstraints==null || basicConstraints.isCA()!=repBasicConstraints.isCA() ){
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"CertRequestMessages.certificate.caExtensionNoMatchingTemplate");
				validationResult.addNotification(msg);
			}
		}		
	}

	protected void checkSerial(
		ProcessingResults<X509CertificateHolder> validationResult) {
		X509CertificateHolder requestedCertificate = validationResult.getReturnValue();
		if(certTemplate.getSerialNumber()!=null &&
				!certTemplate.getSerialNumber().equals(requestedCertificate.getSerialNumber())){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.certificate.serialNumberNoMatchingTemplate");
			validationResult.addNotification(msg);
		}
	}

	protected void checkValidity(
			ProcessingResults<X509CertificateHolder> validationResult) {
		X509CertificateHolder requestedCertificate = validationResult.getReturnValue();
		if (certTemplate.getValidity()!=null){
			OptionalValidityHolder optionalValidityFromTemplate = new OptionalValidityHolder(
					certTemplate.getValidity());
			boolean notBeforeCompatible = OptionalValidityComparator
					.isNotBeforeCompatible(optionalValidityFromTemplate
							.getNotBeforeAsDate(), requestedCertificate
							.getNotBefore());
			boolean notAfterCompatible = OptionalValidityComparator
					.isNotAfterCompatible(optionalValidityFromTemplate
							.getNotAfterAsDate(), requestedCertificate
							.getNotAfter());
			if (!notBeforeCompatible || !notAfterCompatible){
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"CertRequestMessages.certificate.validityNoMatchingTemplate",
						new Object[] {
						optionalValidityFromTemplate.getNotBeforeAsDate(),
						optionalValidityFromTemplate.getNotAfterAsDate(),
						requestedCertificate.getNotBefore(),
						requestedCertificate.getNotAfter()});
				validationResult.addNotification(msg);			
			}
		}
	}

	protected void checkIssuer(
		ProcessingResults<X509CertificateHolder> validationResult) {
		X509CertificateHolder requestedCertificate = validationResult.getReturnValue();
		if (certTemplate.getIssuer()!=null && !certTemplate.getIssuer().equals(
				requestedCertificate.getIssuer())){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.certificate.issuerNoMatchingTemplate");
			validationResult.addNotification(msg);
		}
	}
	
	protected void checkIncludedSubject(
		ProcessingResults<X509CertificateHolder> validationResult){
		X509CertificateHolder requestedCertificate = validationResult.getReturnValue();
		// collect modifications into a validation object and show user 
		// for confirmation.
		if (certTemplate.getSubject()!=null && !certTemplate.getSubject().equals(
				requestedCertificate.getSubject())){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.certificate.subjectNoMatchingTemplate");
			validationResult.addNotification(msg);
		}
	}

	protected void checkPublicKey(
		ProcessingResults<X509CertificateHolder> validationResult) {
		X509CertificateHolder requestedCertificate = validationResult.getReturnValue();
		if (certTemplate.getPublicKey()!=null &&  !certTemplate.getPublicKey().equals(
				requestedCertificate.getSubjectPublicKeyInfo())){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.certificate.publicKeyNoMatchingTemplate");
			validationResult.addError(msg);
			
		}		
	}
}
