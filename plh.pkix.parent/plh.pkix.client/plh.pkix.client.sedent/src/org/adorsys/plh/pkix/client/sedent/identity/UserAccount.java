package org.adorsys.plh.pkix.client.sedent.identity;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;

import org.adorsys.plh.pkix.client.services.Account;
import org.adorsys.plh.pkix.core.utils.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.Md5Utils;
import org.adorsys.plh.pkix.core.utils.store.CertificateStore;
import org.adorsys.plh.pkix.core.utils.store.PrivateKeyHolder;
import org.adorsys.plh.pkix.core.utils.x500.PlhFileExtensions;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

public class UserAccount implements Account {
	
	private final PrivateKey userAccountPrivateKey;
	private final X509CertificateHolder userAccountSelfSignedcertificate;

	private final CertificateStore certificateStore;
	private final PrivateKeyHolder privateKeyHolder;
	
	private final File userAccountDir;
	
	private final DeviceAccount deviceAccount;
	
	public UserAccount(DeviceAccount deviceAccount, String userPersonae, String userAccountName){
		
		this.deviceAccount = deviceAccount;
		DeviceAccountDir deviceAccountDir = deviceAccount.getDeviceAccountDir();
		
		String userAccountFilePrefix = Md5Utils.toMd5StringHex(userAccountName);
		userAccountDir = new File(deviceAccountDir.getDeviceAccountDir(), userAccountFilePrefix + PlhFileExtensions.USER_ACCOUNT_EXT);

		// Initialize the key store
		File userAccountKeystoreBase = new File(userAccountDir, "keystores");
		FileBasedKeyStore fileBasedKeyStore = new FileBasedKeyStore(userAccountKeystoreBase, deviceAccount);
		certificateStore = fileBasedKeyStore;
		privateKeyHolder = fileBasedKeyStore;
		
		// test existence of the account
		X509CertificateHolder certificate = certificateStore.getCertificate(userAccountName, userAccountName);
		
		if(certificate!=null){
			userAccountSelfSignedcertificate = certificate;
			userAccountPrivateKey = privateKeyHolder.getPrivateKey(userAccountSelfSignedcertificate);
		} else {
			// create account key
			X500Name userAccountX500Name = X500NameHelper.makeX500Name(userPersonae, userAccountName);
			new KeyPairBuilder()
				.withEndEntityName(userAccountX500Name)
				.withPrivateKeyHolder(privateKeyHolder)
				.withCertificateStore(certificateStore)
				.build0();
			userAccountSelfSignedcertificate = certificateStore.getCertificate(userAccountName, userAccountName);
			userAccountPrivateKey = privateKeyHolder.getPrivateKey(userAccountSelfSignedcertificate);
		}
	}

	@Override
	public void deviceStoreTo(InputStream inputStream, String relativeOutputPath)
			throws IOException {
		File file = new File(userAccountDir, relativeOutputPath);
		if(!file.exists()) file.getParentFile().mkdirs();
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(file);
			deviceAccount.signEncrypt(inputStream, fos);
		} finally {
			IOUtils.closeQuietly(fos);
		}
	}

	@Override
	public void deviceLoadFrom(String relativeInputPath,
			OutputStream outputStream) throws IOException {
		File file = new File(userAccountDir, relativeInputPath);
		if(!file.exists()) throw new FileNotFoundException(file.getAbsolutePath());
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			deviceAccount.decrypVerify(fis, outputStream);
		} finally {
			fis.close();
		}
	}
}
