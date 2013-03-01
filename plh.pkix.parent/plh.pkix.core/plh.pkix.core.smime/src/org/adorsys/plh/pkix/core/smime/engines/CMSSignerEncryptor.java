package org.adorsys.plh.pkix.core.smime.engines;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;

public class CMSSignerEncryptor {

	private CMSPart inputPart;
	private List<X509Certificate> recipientCertificates;
	private Certificate[] signerCertificateChain;
	
	private final BuilderChecker checker = new BuilderChecker(CMSSignerEncryptor.class);
	public CMSPart signEncrypt(PrivateKey privateKey) {
		checker.checkDirty()
			.checkNull(privateKey, inputPart,recipientCertificates, signerCertificateChain)
			.checkEmpty(recipientCertificates)
			.checkEmpty(signerCertificateChain);
		
		// Sign the file
//		File signedFile;
//		try {
//			signedFile = File.createTempFile(UUID.randomUUID().toString(), null);
//		} catch (IOException e) {
//			throw new IllegalStateException(e);
//		}
		
		CMSPart outputPart;
		try {
			// TODO: wrap this in an encrypted stream to protect file on device
//			signedOutputStream = new FileOutputStream(signedFile);
			outputPart = new CMSSigner()
			.withInputPart(inputPart)
//			.withOutputStream(signedOutputStream)
			.withSignerCertificateChain(signerCertificateChain)
			.sign(privateKey);
//		} catch (FileNotFoundException e) {
//			FileUtils.deleteQuietly(signedFile);
//			throw new IllegalStateException(e);
		} catch (RuntimeException e){
//			FileUtils.deleteQuietly(signedFile);
			throw e;
		}
		
		// encrypt the file
//		InputStream signedInputStream = null;
		try {
//			signedInputStream = new FileInputStream(signedFile);
			return new CMSEncryptor()
				.withInputPart(outputPart)
//				.withOutputStream(outputStream)
				.withRecipientCertificates(recipientCertificates)
				.encrypt();
//		} catch (FileNotFoundException e) {
//			throw new IllegalStateException(e);
//		} catch (RuntimeException e){
//			throw e;
		} finally {
			outputPart.dispose();
//			FileUtils.deleteQuietly(signedFile);
//			IOUtils.closeQuietly(signedInputStream);
		}
	}

	public CMSSignerEncryptor withInputPart(CMSPart inputPart) {
		this.inputPart = inputPart;
		return this;
	}

	public CMSSignerEncryptor withRecipientCertificates(List<X509Certificate> recipientCertificates) {
		this.recipientCertificates = recipientCertificates;
		return this;
	}

	public CMSSignerEncryptor withSignerCertificateChain(Certificate[] signerCertificateChain) {
		this.signerCertificateChain = signerCertificateChain;
		return this;
	}
}
