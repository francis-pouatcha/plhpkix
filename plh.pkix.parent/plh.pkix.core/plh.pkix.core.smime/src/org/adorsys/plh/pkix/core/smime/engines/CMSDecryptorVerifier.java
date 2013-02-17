package org.adorsys.plh.pkix.core.smime.engines;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.X509CRL;

import javax.security.auth.callback.CallbackHandler;

import org.adorsys.plh.pkix.core.smime.validator.CMSPart;
import org.adorsys.plh.pkix.core.smime.validator.CMSSignedMessageValidator;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;

public class CMSDecryptorVerifier {
	
	private KeyStore keyStore;
	private X509CRL crl;
	private CallbackHandler callbackHandler;
	private CMSPart inputPart;
	
	private final BuilderChecker checker = new BuilderChecker(CMSDecryptorVerifier.class);
	public CMSSignedMessageValidator<CMSPart> decryptVerify() {
		checker.checkDirty()
			.checkNull(keyStore, callbackHandler,inputPart);//,outputStream);
		
		// Decrypt the file. // TODO encryp tmp steams to protect plain text on device.
//		File decryptedFile;
//		try {
//			decryptedFile = File.createTempFile(UUID.randomUUID().toString(), null);
//		} catch (IOException e) {
//			throw new IllegalStateException(e);
//		}
		
//		OutputStream decryptedOutputStream = null;
		CMSPart decryptedPart = null;
//		try {
//			decryptedOutputStream = new FileOutputStream(decryptedFile);
		decryptedPart = new CMSDecryptor()
				.withKeyStore(keyStore)
				.withCallbackHandler(callbackHandler)
				.withInputPart(inputPart)
				.decrypt();
//		} catch (FileNotFoundException e) {
////			FileUtils.deleteQuietly(decryptedFile);
//			throw new IllegalStateException(e);// file must still exists
//		} catch(RuntimeException e){
////			FileUtils.deleteQuietly(decryptedFile);
//			throw e;
//		} finally {
////			IOUtils.closeQuietly(decryptedOutputStream);
//		}
		
		try {
			return new CMSVerifier()
				.withCrl(crl)
				.withKeyStore(keyStore)
				.withInputPart(decryptedPart)
				.readAndVerify();
		} catch (FileNotFoundException e) {
			throw new IllegalStateException(e);// file must still exists
		} catch (IOException e) {
			throw new IllegalArgumentException(e);// can not write to output stream
		} catch(RuntimeException e){
			throw e;
		} finally {
			decryptedPart.dispose();
//			FileUtils.deleteQuietly(decryptedFile);
//			IOUtils.closeQuietly(decryptedInputStream);
		}
	}

	public CMSDecryptorVerifier withKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
		return this;
	}

	public CMSDecryptorVerifier withCrl(X509CRL crl) {
		this.crl = crl;
		return this;
	}

	public CMSDecryptorVerifier withCallbackHandler(CallbackHandler callbackHandler) {
		this.callbackHandler = callbackHandler;
		return this;
	}

	public CMSDecryptorVerifier withInputPart(CMSPart inputPart) {
		this.inputPart = inputPart;
		return this;
	}
}
