package org.adorsys.plh.pkix.core.test.cms.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.util.Arrays;
import java.util.List;

import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Ignore;
import org.junit.Test;

public class SingEncryptScenarioTests {

	static Provider provider = PlhCMPSystem.getProvider();
	static char[] password = PlhCMPSystem.getServerPassword();
	
	static final String file1 = "test/resources/rfc4210.pdf";
	static final String file2 = "test/resources/rfc5652CMS.pdf";
	
	@Test
	@Ignore()// Must wait for server mock to exchange certificate
	public void testTimAndAlex() throws IOException {
		X500Name timNameX500= X500NameHelper.makeX500Name("tim", "tim@plhtest.biz");
		X500Name alexNameX500=X500NameHelper.makeX500Name("alex", "alex@plhtest.biz");
		CryptoClient tim = new CryptoClient(timNameX500, new PrivateKeyHolder(), new CertificateStore());
		CryptoClient alex = new CryptoClient(alexNameX500, new PrivateKeyHolder(), new CertificateStore());
		
		List<X500Name> reciepientNamesX500 = Arrays.asList(alexNameX500);
		File fileSentByTim = new File(file1);
		InputStream sentInputStream = new FileInputStream(file1);
		File fileSentByTimToAlex = new File("target/"+fileSentByTim.getName()+".sentByTimToAlex.signed.encrypted");
		OutputStream sentOutputStream = new FileOutputStream(fileSentByTimToAlex );
		tim.sendFile(reciepientNamesX500, sentInputStream, sentOutputStream);
		
		InputStream recievedInputStream = new FileInputStream(fileSentByTimToAlex.getAbsolutePath());
		File fileRecievedByAlexFromTim = new File("target/"+fileSentByTim.getName()+".recievedByAlexFromTim.signed.encrypted");
		OutputStream recivedOutputStream = new FileOutputStream(fileRecievedByAlexFromTim);
		alex.receiveFile(recievedInputStream, recivedOutputStream);
	
	}

}
