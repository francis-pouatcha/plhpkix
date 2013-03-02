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

}
