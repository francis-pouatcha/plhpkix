package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.util.List;

import org.adorsys.plh.pkix.core.cmp.certrequest.CertRequestMessages;
import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityComparator;
import org.adorsys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.adorsys.plh.pkix.core.utils.action.ProcessingResults;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
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
public class CertificationReplyValidator {
	private static final String RESOURCE_NAME = CertRequestMessages.class.getName();

	private final BuilderChecker checker = new BuilderChecker(CertificationReplyValidator.class);

	private CertTemplate certTemplate;

	public void validate(final ProcessingResults<List<X509CertificateHolder>> validationResult){
		checker.checkDirty()
			.checkNull(certTemplate,validationResult);

		List<X509CertificateHolder> certificateChain = validationResult.getReturnValue();
		X509CertificateHolder repliedCertificate = certificateChain.get(0);
		// collect modifications into a validation object and show user 
		// for confirmation.
		if (certTemplate.getSubject()!=null && !certTemplate.getSubject().equals(
				repliedCertificate.getSubject())){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.certificate.subjectNoMatchingTemplate");
			validationResult.addNotification(msg);
		}

		if (certTemplate.getPublicKey()!=null &&  !certTemplate.getPublicKey().equals(
				repliedCertificate.getSubjectPublicKeyInfo())){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.certificate.publicKeyNoMatchingTemplate");
			validationResult.addError(msg);
			
		}

		if (certTemplate.getIssuer()!=null && !certTemplate.getIssuer().equals(
				repliedCertificate.getIssuer())){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.certificate.issuerNoMatchingTemplate");
			validationResult.addNotification(msg);
			
		}

		if (certTemplate.getValidity()!=null){
			OptionalValidityHolder optionalValidityFromTemplate = new OptionalValidityHolder(
					certTemplate.getValidity());
			boolean notBeforeCompatible = OptionalValidityComparator
					.isNotBeforeCompatible(optionalValidityFromTemplate
							.getNotBeforeAsDate(), repliedCertificate
							.getNotBefore());
			boolean notAfterCompatible = OptionalValidityComparator
					.isNotAfterCompatible(optionalValidityFromTemplate
							.getNotAfterAsDate(), repliedCertificate
							.getNotAfter());
			if (!notBeforeCompatible || !notAfterCompatible){
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"CertRequestMessages.certificate.validityNoMatchingTemplate",
						new Object[] {
						optionalValidityFromTemplate.getNotBeforeAsDate(),
						optionalValidityFromTemplate.getNotAfterAsDate(),
						repliedCertificate.getNotBefore(),
						repliedCertificate.getNotAfter()});
				validationResult.addNotification(msg);			
			}
		}
		
		if(certTemplate.getSerialNumber()!=null &&
				!certTemplate.getSerialNumber().equals(repliedCertificate.getSerialNumber())){
			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
					"CertRequestMessages.certificate.serialNumberNoMatchingTemplate");
			validationResult.addNotification(msg);
		}

		
		Extensions certTemplateExtensions = certTemplate.getExtensions();
		Extension basicConstraintsExtension = certTemplateExtensions.getExtension(X509Extension.basicConstraints);
		BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
		if(basicConstraints!=null){
			Extension repBasicConstraintsExtension = repliedCertificate.getExtension(X509Extension.basicConstraints);
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

		Extension subjectAlternativeNameExtension = certTemplateExtensions.getExtension(X509Extension.subjectAlternativeName);
		if(subjectAlternativeNameExtension!=null) {
			GeneralNames subjectAltName = GeneralNames.getInstance(subjectAlternativeNameExtension.getParsedValue());
			Extension repSubjectAlternativeNameExtension = repliedCertificate.getExtension(X509Extension.subjectAlternativeName);
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
	
		int keyUsage = KeyUsageUtils.getKeyUsage(certTemplateExtensions);
		if(keyUsage>-1){
			int keyUsage2 = KeyUsageUtils.getKeyUsage(repliedCertificate);
			if(keyUsage!=keyUsage2){
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
						"CertRequestMessages.certificate.keyUsageExtensionNoMatchingTemplate");
				validationResult.addNotification(msg);
			}

		}
	
		Extension authorityInfoAccessExtension = certTemplateExtensions.getExtension(X509Extension.authorityInfoAccess);
		if(authorityInfoAccessExtension!=null){
			AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(authorityInfoAccessExtension.getParsedValue());
			Extension repAuthorityInfoAccessExtension = repliedCertificate.getExtension(X509Extension.authorityInfoAccess);
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

	public CertificationReplyValidator withCertTemplate(CertTemplate certTemplate) {
		this.certTemplate = certTemplate;
		return this;
	}
}
