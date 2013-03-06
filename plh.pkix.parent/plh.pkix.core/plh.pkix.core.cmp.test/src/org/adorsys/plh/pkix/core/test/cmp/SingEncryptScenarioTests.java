package org.adorsys.plh.pkix.core.test.cmp;

import java.io.File;
import java.io.IOException;

import org.adorsys.plh.pkix.core.cmp.CMPAccount;
import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.cmp.CMPandCMSClient;
import org.adorsys.plh.pkix.core.cmp.InMemoryCMPMessenger;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.InitializationRequestFieldHolder;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.Test;

public class SingEncryptScenarioTests {

	static final String srcFile1 = "test/resources/rfc4210.pdf";
	static final String srcFile2 = "test/resources/rfc5652CMS.pdf";
	
	@Test
	public void testTimAndAlex() throws IOException {
		
		File workspaceDir = new File("target/SingEncryptScenarioTests/testTimAndAlex");
		CMPMessenger cmpMessenger = new InMemoryCMPMessenger();
		
		CMPandCMSClient certAuthClient = new CMPandCMSClient(cmpMessenger, workspaceDir, 
				"certAuthComputer", "certAuthContainerKeyPass".toCharArray(), "certAuthContainerStorePass".toCharArray());
		CMPAccount certAuthAccount = certAuthClient.newAccount("Adorsys Certification Authority", "certAuth@adorsys.com", "certAuthAccountPassword".toCharArray());
		certAuthAccount.registerAccount();

		CMPandCMSClient timClient = new CMPandCMSClient(cmpMessenger, workspaceDir, 
				"timsComputer", "timsContainerKeyPass".toCharArray(), "timsContainerStorePass".toCharArray());
		CMPAccount timsAccount = timClient.newAccount("Tim Tester", "tim@adorsys.com", "TimsAccountPassword".toCharArray());
		timsAccount.registerAccount();

		CMPandCMSClient alexClient = new CMPandCMSClient(cmpMessenger, workspaceDir, 
				"alexesComputer", "alexesContainerKeyPass".toCharArray(), "alexesContainerStorePass".toCharArray());
		CMPAccount alexesAccount = alexClient.newAccount("Alex Tester", "alex@adorsys.com", "AlexesAccountPassword".toCharArray());
		alexesAccount.registerAccount();
		
		
		InitializationRequestFieldHolder f = new InitializationRequestFieldHolder();
		f.setReceiverEmail("certAuth@adorsys.com");
		GeneralName gn = new GeneralName(GeneralName.rfc822Name, "certAuth@adorsys.com");
		GeneralNames subjectAltNames = new GeneralNames(gn);
		f.setSubjectAltNames(subjectAltNames);
		// certification request
		timsAccount.sendInitializationRequest(f);
		FileUtils.deleteQuietly(workspaceDir);
	}		
//		String caCN="certAuth@plpkixhtest.biz";
//		CMPandCMSClient caClient = new CMPandCMSClient(clients);
//		caClient.register("certAuth", caCN);
//
//		String timCN = "tim@plpkixhtest.biz";
//		CMPandCMSClient timClient = new CMPandCMSClient(clients);
//		timClient.register("tim", timCN);
//		timClient.requestCertification(caCN);
//
//		String alexCN = "alex@plpkixhtest.biz";
//		CMPandCMSClient alexClient = new CMPandCMSClient(clients);
//		alexClient.register("alex", alexCN);
//		alexClient.requestCertification(caCN);
//		
//		// certificate exchange
//		alexClient.fetchCertificate(timCN, caCN);
//		timClient.fetchCertificate(alexCN, caCN);
//		
//		
//		File fileSentByTim = new File(srcFile1);
//		InputStream sentInputStream = new FileInputStream(srcFile1);
//		String fileSentByTimToAlexName = "target/"+fileSentByTim.getName()+".sentByTimToAlex.signed.encrypted";
//		File fileSentByTimToAlex = new File(fileSentByTimToAlexName);
//		OutputStream sentOutputStream = new FileOutputStream(fileSentByTimToAlex );
//		timClient.sendFile(caCN,sentInputStream, sentOutputStream, alexCN);
//		IOUtils.closeQuietly(sentInputStream);
//		IOUtils.closeQuietly(sentOutputStream);
//		
//		InputStream recievedInputStream = new FileInputStream(fileSentByTimToAlexName);
//		File fileRecievedByAlexFromTim = new File("target/"+fileSentByTim.getName()+".recievedByAlexFromTim.decrypted.verified");
//		OutputStream recivedOutputStream = new FileOutputStream(fileRecievedByAlexFromTim);
//		alexClient.receiveFile(recievedInputStream, recivedOutputStream);
//		IOUtils.closeQuietly(recievedInputStream);
//		IOUtils.closeQuietly(recivedOutputStream);
//	
//		boolean contentEquals = FileUtils.contentEquals(
//				new File(srcFile1), 
//				new File(fileRecievedByAlexFromTim.getAbsolutePath()));
//		Assert.assertTrue(contentEquals);
//	}
//
//
//	@Test
//	public void testTimAndTim() throws IOException {
//		ClientMap clients = new ClientMap();
//		String caCN="certAuth@plpkixhtest.biz";
//		CMPandCMSClient caClient = new CMPandCMSClient(clients);
//		caClient.register("certAuth", caCN);
//
//		String timCN = "tim@plpkixhtest.biz";
//		CMPandCMSClient timClient = new CMPandCMSClient(clients);
//		timClient.register("tim", timCN);
//		timClient.requestCertification(caCN);
//		
//		File fileSentByTim = new File(srcFile1);
//		InputStream sentInputStream = new FileInputStream(srcFile1);
//		String fileSentByTimToTimName = "target/"+fileSentByTim.getName()+".sentByTimToTim.signed.encrypted";
//		File fileSentByTimToTim = new File(fileSentByTimToTimName);
//		OutputStream sentOutputStream = new FileOutputStream(fileSentByTimToTim );
//		timClient.sendFile(caCN,sentInputStream, sentOutputStream, timCN);
//		IOUtils.closeQuietly(sentInputStream);
//		IOUtils.closeQuietly(sentOutputStream);
//		
//		InputStream recievedInputStream = new FileInputStream(fileSentByTimToTimName);
//		String fileRecievedByTimFromTimName = "target/"+fileSentByTim.getName()+".recievedByTimFromTim.decrypted.verified";
//		File  fileRecievedByTimFromTim = new File(fileRecievedByTimFromTimName);
//		OutputStream recivedOutputStream = new FileOutputStream(fileRecievedByTimFromTim);
//		timClient.receiveFile(recievedInputStream, recivedOutputStream);
//		IOUtils.closeQuietly(recievedInputStream);
//		IOUtils.closeQuietly(recivedOutputStream);
//	
//		boolean contentEquals = FileUtils.contentEquals(
//				new File(srcFile1), 
//				new File(fileRecievedByTimFromTim.getAbsolutePath()));
//		Assert.assertTrue(contentEquals);
//	}
}
