package org.adorsys.plh.pkix.client.sedent.identity;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;

import org.adorsys.plh.pkix.core.cms.utils.SignEncryptUtils;
import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.keypair.KeyPairBuilder;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.adorys.plh.pkix.core.cmp.utils.PrivateKeyUtils;
import org.adorys.plh.pkix.core.cmp.utils.V3CertificateUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

public class DeviceAccount {

	private final AccountDir accountDir;

	private Provider provider = PlhCMPSystem.getProvider();
	
	private final PrivateKey accountDevicePrivateKey;
	private final X509CertificateHolder accountDeviceCertificate;
	private final String accountCN;

	private final CertificateStore certificateStore = new CertificateStore();
	private final PrivateKeyHolder privateKeyHolder = new PrivateKeyHolder();
	
	public DeviceAccount(AccountDir accountDir, char[] accountPassword) {
		this.accountDir = accountDir;
		File terminalPrivateFile = new File(accountDir.getAccountRootDir(), "private");
		File terminalPublicKeyFile = new File(accountDir.getAccountRootDir(), "public");
		if(!terminalPublicKeyFile.exists()){
			CertificateStore certificateStore = new CertificateStore();
			PrivateKeyHolder privateKeyHolder = new PrivateKeyHolder();
			X500Name accountX500Name = X500NameHelper.makeX500Name(accountDir.getDeviceName(), accountDir.getAccountName());
			this.accountCN = X500NameHelper.getCN(accountX500Name);
			new KeyPairBuilder()
				.withCertificateStore(certificateStore)
				.withPrivateKeyHolder(privateKeyHolder)
				.withEndEntityName(accountX500Name)
				.build0();
			accountDeviceCertificate = certificateStore.getCertificate(accountX500Name);
			accountDevicePrivateKey = privateKeyHolder.getPrivateKey(accountDeviceCertificate);
		} else {
			if(!terminalPublicKeyFile.exists())
				throw new IllegalStateException("Missing device public key file for account: " + accountDir.getAccountName());
		
			try {
				accountDevicePrivateKey = PrivateKeyUtils.decryptPrivateKey(FileUtils.readFileToByteArray(terminalPrivateFile), accountPassword, provider);
				byte[] terminalPublicKeyByteArray = FileUtils.readFileToByteArray(terminalPublicKeyFile);
				accountDeviceCertificate = new X509CertificateHolder(terminalPublicKeyByteArray);
				accountCN = X500NameHelper.getCN(accountDeviceCertificate.getSubject());
				// WARNING: this code might break if logic for CN initialization changes X500NameHelper
				if(StringUtils.equalsIgnoreCase(accountDir.getAccountName(), accountCN)){
					throw new SecurityException("Account name shall be identical to accoutn CN, ase insensitive");
				}
				V3CertificateUtils.checkSelfSigned(accountDeviceCertificate, 
						accountDir.getAccountName(), accountDir.getAccountName(), provider);
			} catch (Exception e) {
				throw new IllegalStateException(e);
			}
		
		}

		certificateStore.addCertificate(accountDeviceCertificate);
		privateKeyHolder.addKeyPair(accountDevicePrivateKey, accountDeviceCertificate);
	}
	
	/**
	 * Sign, Encrypt and store the file under the given name
	 * @param relativeFilePath
	 * @return
	 * @throws IOException 
	 */
	public void signEncrypt(InputStream inputStream, OutputStream outputStream) throws IOException{
		SignEncryptUtils.signEncrypt(privateKeyHolder, 
				accountDeviceCertificate, inputStream, outputStream, certificateStore, accountCN);
	}
	
	public void decrypVerify(InputStream inputStream, OutputStream outputStream) throws IOException{
		SignEncryptUtils.decryptVerify(privateKeyHolder, accountCN, certificateStore, inputStream, outputStream);
	}
	
	public File getAccountRootDir(){
		return accountDir.getAccountRootDir();
	}
	
	public static String getTopicName(){
		String name = DeviceAccount.class.getName();
		return name.replace(".", "_");
	}
}
