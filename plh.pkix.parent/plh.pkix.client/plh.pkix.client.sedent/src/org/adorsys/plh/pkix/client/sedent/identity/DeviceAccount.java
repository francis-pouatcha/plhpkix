package org.adorsys.plh.pkix.client.sedent.identity;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;

import org.adorsys.plh.pkix.client.services.Device;
import org.adorsys.plh.pkix.core.smime.CMSSignEncryptUtils;
import org.adorsys.plh.pkix.core.utils.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.Md5Utils;
import org.adorsys.plh.pkix.core.utils.PrivateKeyUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.store.CertificateStore;
import org.adorsys.plh.pkix.core.utils.store.InMemoryCertificateStore;
import org.adorsys.plh.pkix.core.utils.store.InMemoryPrivateKeyHolder;
import org.adorsys.plh.pkix.core.utils.store.PrivateKeyHolder;
import org.adorsys.plh.pkix.core.utils.x500.PlhFileExtensions;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Holds information on a device account.
 * 
 * @author francis
 *
 */
public class DeviceAccount implements Device {

	public static final String TOPIC_NAME = "org_adorsys_plh_pkix_client_sedent_identity_DeviceAccount";

	private final DeviceAccountDir deviceAccountDir;

	private Provider provider = ProviderUtils.bcProvider;
	
	private final PrivateKey deviceAccountPrivateKey;
	private final X509CertificateHolder deviceAccountCertificate;
	private final String deviceAccountCN;

	private final CertificateStore deviceAccountCertificateStore = new InMemoryCertificateStore();
	private final PrivateKeyHolder deviceAccountPrivateKeyHolder = new InMemoryPrivateKeyHolder();
	
	public DeviceAccount(DeviceAccountDir deviceAccountDir, char[] deviceAccountPassword) {
		this.deviceAccountDir = deviceAccountDir;
		String deviceKeyPrefix = Md5Utils.toMd5StringHex(deviceAccountDir.getDeviceAccountRootDir().getDeviceIdentity());
		File deviceAccountKeystoreDir = new File(deviceAccountDir.getDeviceAccountDir(), deviceKeyPrefix+PlhFileExtensions.KEY_STORE_DIR_EXT);
		File deviceAccountPrivateKeyFile = new File(deviceAccountKeystoreDir, deviceKeyPrefix+PlhFileExtensions.PRIVATE_KEY_ENCRYPTED_EXT);
		File deviceAccountSelfCertificateFile = new File(deviceAccountKeystoreDir, deviceKeyPrefix + PlhFileExtensions.CERTIFICATE_EXT);
		if(!deviceAccountPrivateKeyFile.exists()){
			X500Name deviceAccountX500Name = X500NameHelper.makeX500Name(deviceAccountDir.getDeviceAccountName(), deviceAccountDir.getDeviceAccountName());
			this.deviceAccountCN = X500NameHelper.getCN(deviceAccountX500Name);
			new KeyPairBuilder()
				.withCertificateStore(deviceAccountCertificateStore)
				.withPrivateKeyHolder(deviceAccountPrivateKeyHolder)
				.withEndEntityName(deviceAccountX500Name)
				.build0();
			deviceAccountCertificate = deviceAccountCertificateStore.getCertificate(deviceAccountX500Name);
			deviceAccountPrivateKey = deviceAccountPrivateKeyHolder.getPrivateKey(deviceAccountCertificate);
			deviceAccountKeystoreDir.mkdir();
			try {
				byte[] encryptedPrivateKeyBytes = PrivateKeyUtils.encryptPrivateKey(deviceAccountPrivateKey, provider, deviceAccountPassword);
				FileUtils.writeByteArrayToFile(deviceAccountPrivateKeyFile, encryptedPrivateKeyBytes);
				FileUtils.writeByteArrayToFile(deviceAccountSelfCertificateFile, deviceAccountCertificate.getEncoded());
			} catch (Exception e) {
				throw new IllegalStateException(e);
			}
			
		} else {
			if(!deviceAccountSelfCertificateFile.exists())
				throw new IllegalStateException("Missing device public key file for account: " + deviceAccountDir.getDeviceAccountName());
		
			try {
				deviceAccountPrivateKey = PrivateKeyUtils.decryptPrivateKey(FileUtils.readFileToByteArray(deviceAccountPrivateKeyFile), deviceAccountPassword, provider);
				byte[] deviceAccountPublicKeyByteArray = FileUtils.readFileToByteArray(deviceAccountSelfCertificateFile);
				deviceAccountCertificate = new X509CertificateHolder(deviceAccountPublicKeyByteArray);
				deviceAccountCN = X500NameHelper.getCN(deviceAccountCertificate.getSubject());
				// WARNING: this code might break if logic for CN initialization changes X500NameHelper
				if(!StringUtils.equalsIgnoreCase(deviceAccountDir.getDeviceAccountName(), deviceAccountCN)){
					throw new SecurityException("Account name shall be identical to accoutn CN, ase insensitive");
				}
				V3CertificateUtils.checkSelfSigned(deviceAccountCertificate, 
						deviceAccountDir.getDeviceAccountName(), deviceAccountDir.getDeviceAccountName(), provider);
			} catch (Exception e) {
				throw new IllegalStateException(e);
			}

			deviceAccountCertificateStore.addCertificate(deviceAccountCertificate);
			deviceAccountPrivateKeyHolder.addKeyPair(deviceAccountPrivateKey, deviceAccountCertificate);
		}

	}
	
	/**
	 * Sign, Encrypt and store the file under the given name
	 * @param relativeFilePath
	 * @return
	 * @throws IOException 
	 */
	public void signEncrypt(InputStream inputStream, OutputStream outputStream) throws IOException{
		CMSSignEncryptUtils.signEncrypt(deviceAccountPrivateKeyHolder, 
				deviceAccountCertificate, inputStream, outputStream, deviceAccountCertificateStore, deviceAccountCN);
	}
	
	public void decrypVerify(InputStream inputStream, OutputStream outputStream) throws IOException{
		CMSSignEncryptUtils.decryptVerify(deviceAccountPrivateKeyHolder, deviceAccountCN, deviceAccountCertificateStore, inputStream, outputStream);
	}
	
	public DeviceAccountDir getDeviceAccountDir(){
		return deviceAccountDir;
	}
}
