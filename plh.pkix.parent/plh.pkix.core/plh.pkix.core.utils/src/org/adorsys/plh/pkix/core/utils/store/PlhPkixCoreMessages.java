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

	public static final String KeyAliasUtils_cn_addressException = "KeyAliasUtils.cn.addressException";

	public static final String V3CertificateUtils_read_generalCertificateException = "V3CertificateUtils.convert.generalCertificateException";
	public static final String V3CertificateUtils_read_invalidCertificate = "V3CertificateUtils.read.invalidCertificate";

}
