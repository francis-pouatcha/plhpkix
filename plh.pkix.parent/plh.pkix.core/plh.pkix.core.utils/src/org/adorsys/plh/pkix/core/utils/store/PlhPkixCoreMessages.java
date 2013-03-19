package org.adorsys.plh.pkix.core.utils.store;

public interface PlhPkixCoreMessages {
	
	// checked
	public static final String KeyStoreWraper_certImport_invalidSignature = "KeyStoreWraper.certImport.invalidSignature";
	public static final String KeyStoreWraper_certImport_invalidCertificate = "KeyStoreWraper.certImport.invalidCertificate";

	
	// Unchecked exception
	public static final String KeyStoreWraper_certImport_keystoreException = "KeyStoreWraper.certImport.keystoreException";
	public static final String KeyStoreWraper_certImport_certVerifyException = "KeyStoreWraper.certImport.certException";
	public static final String KeyStoreWraper_certImport_generalCertificateException = "KeyStoreWraper.certImport.generalCertificateException";
	public static final String KeyStoreWraper_read_keystoreException = "KeyStoreWraper.certImport.keystoreException";
	public static final String KeyStoreWraper_certImport_missingPrivateKeyEntry = "KeyStoreWraper.certImport.missingPrivateKeyEntry";

	public static final String KeyAliasUtils_cn_addressException = "KeyAliasUtils.cn.addressException";

	public static final String V3CertificateUtils_read_generalCertificateException = "V3CertificateUtils.convert.generalCertificateException";
	public static final String V3CertificateUtils_read_invalidCertificate = "V3CertificateUtils.read.invalidCertificate";

	public static final String X509CertificateBuilder_missing_inputs = "X509CertificateBuilder.missing.inputs";
	public static final String X509CertificateBuilder_missing_subject_publicKey = "X509CertificateBuilder.missing.subjectPublicKey";
	public static final String X509CertificateBuilder_missing_subject_DN = "X509CertificateBuilder.missing.subjectDN";
	public static final String X509CertificateBuilder_missing_validity_date_notBefore = "X509CertificateBuilder.missing.validityDate.notBefore";
	public static final String X509CertificateBuilder_missing_validity_date_notAfter = "X509CertificateBuilder.missing.validityDate.notAfter";
	public static final String X509CertificateBuilder_issuerCert_invalid = "X509CertificateBuilder.issuerCert.invalid";
	public static final String X509CertificateBuilder_issuerCert_notCaCert = "X509CertificateBuilder.issuerCert.notCaCert";
	public static final String X509CertificateBuilder_issuerCert_notForCertSign = "X509CertificateBuilder.issuerCer.notForCertSign";

	/**
	 * Exception retrieving the signer's certificate. Message should be rejected if this
	 * happens. No need to fetch the user decision. Either the signer certificate comes
	 * with the message or it is already in the database.
	 */
	public static final String SignatureValidator_exceptionRetrievingSignerCert="SignatureValidator.exceptionRetrievingSignerCert";

	/**
	 * Thrown when the cert path review can not validate the cert path. Message has to be displayed to the user,
	 * so the user can take a decision on how to process.
	 * 
	 * For example in a CMP initialization request, the response might be signed from a certificate that is not yet known to
	 * the client. Special processor will check is the certificate sent to the user as a response to the initialization can be used
	 * to validate the message signature. In which case the message will be processed as if send with a valid signature.
	 */
	public static final String SignatureValidator_certPathInvalid="SignatureValidator.certPathInvalid";
	
//	public static final String SignatureValidator_exceptionCreateCertPath="SignatureValidator.exceptionCreateCertPath";
	/**
	 * Signer certificate is neither in our store, nor in the message. This will generally lead to the rejection of the message.
	 */
	public static final String SignatureValidator_noSignerCert = "SignatureValidator.noSignerCert";
	
	/**
	 * Warning the the signing key is too short.
	 */
	public static final String SignatureValidator_shortSigningKey="SignatureValidator.shortSigningKey";
	
	/**
	 * Warning that the certificate validity date is too long.
	 */
	public static final String SignatureValidator_longValidity="SignatureValidator.longValidity";
	
	/**
	 * Error, certificate not for siging a message. Message must be rejected.
	 */
	public static final String SignatureValidator_signingNotPermitted="SignatureValidator.signingNotPermitted";
	
	/**
	 * Key not for message protection, message must be rejected.
	 */
	public static final String SignatureValidator_extKeyUsageNotPermitted="SignatureValidator.extKeyUsageNotPermitted";
	
	/**
	 * Can not read extended key usage. Message must be dropped.
	 */
	public static final String SignatureValidator_extKeyUsageError="SignatureValidator.extKeyUsageError";
	
	/**
	 * Required signed not in the list.
	 */
	public static final String SignatureValidator_wrongSigner="SignatureValidator.wrongSigner";
	
	/**
	 * Certificate expired at signing time.
	 */
	public static final String SignatureValidator_certExpired="SignatureValidator.certExpired";
	
	/**
	 * Cert not yet valid at signing time.
	 */
	public static final String SignatureValidator_certNotYetValid="SignatureValidator.certNotYetValid";
	
	/**
	 * Signature could not be verified.
	 */
	public static final String SignatureValidator_signatureNotVerified="SignatureValidator.signatureNotVerified";
	
	/**
	 * Exception verifying user signature. Message will be discarded.
	 */
	public static final String SignatureValidator_exceptionVerifyingSignature="SignatureValidator.exceptionVerifyingSignature";
	
	public static final String SignatureValidator_signedReceiptRequest="SignatureValidator.signedReceiptRequest";
	public static final String SignatureValidator_noSigningTime="SignatureValidator.noSigningTime";
//	public static final String SignatureValidator_noSenderAddressInCert="SignatureValidator.noSenderAddressInCert";

	
	public static final String PlhUncheckedException_uncaught_exception="PlhUncheckedException.uncaught.exception";

}
