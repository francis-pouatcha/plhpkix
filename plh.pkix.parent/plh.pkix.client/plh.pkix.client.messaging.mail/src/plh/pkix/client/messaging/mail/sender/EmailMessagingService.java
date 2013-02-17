package plh.pkix.client.messaging.mail.sender;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.mail.Address;
import javax.mail.BodyPart;
import javax.mail.Message.RecipientType;
import javax.mail.MessagingException;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.adorsys.plh.pkix.client.services.MessageProcessor;
import org.adorsys.plh.pkix.client.services.MessagingService;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.store.PrivateKeyHolder;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

import plh.pkix.client.messaging.mail.utils.PloohEmailSecrets;
import plh.pkix.client.messaging.mail.utils.SMTPSender;

public class EmailMessagingService implements MessagingService {

//	private final X509CertificateHolder senderCertificateHolder;
	private final Provider provider = ProviderUtils.bcProvider;
	private final X500Name sender;
	private final Address senderEmail;
	private final PrivateKey privateKey;
	private final X509Certificate senderCertificate;
	private final X500Name issuer;
	private final X509Certificate issuerCertificate;
	
	private final PloohEmailSecrets ploohEmailSecrets;
	
	
	public EmailMessagingService(X509CertificateHolder senderCertificateHolder, 
			PrivateKeyHolder privateKeyHolder, 
			X509CertificateHolder issuerCertificateHolder, 
			PloohEmailSecrets ploohEmailSecrets) 
	{
		super();
		this.sender = senderCertificateHolder.getSubject();
		this.issuer = issuerCertificateHolder.getSubject();
		try {
			this.senderEmail = new InternetAddress(X500NameHelper.getCN(sender));
		} catch (AddressException e) {
			throw new IllegalArgumentException("Common name of the sender X500Name must be a well formed email address", e);
		}
		this.privateKey = privateKeyHolder.getPrivateKey(senderCertificateHolder);
		this.senderCertificate = V3CertificateUtils.getCertificate(senderCertificateHolder, provider);
		this.issuerCertificate = V3CertificateUtils.getCertificate(issuerCertificateHolder, provider);
		this.ploohEmailSecrets = ploohEmailSecrets;
	}

	@Override
	public void send(String recipients, String subject, String plainText,
			String htmlText,List<DataSource> attchements) 
	{

		SMTPSender smtpSender = SMTPSender.newSender(ploohEmailSecrets);

		MimeMessage mimeMsessage = smtpSender.createMimeMessage();
        
		try {
			mimeMsessage.setFrom(senderEmail);
			mimeMsessage.setSubject(subject);

			if (recipients != null) {
				String[] emails = recipients.split(",");
				ArrayList<InternetAddress> arrayList = new ArrayList<InternetAddress>();
				for (int i = 0; i < emails.length; i++) {
					try {
						arrayList.add(new InternetAddress(emails[i]));
					} catch(Exception e){
						throw new IllegalArgumentException(e);
					}
				}
				if(arrayList.isEmpty()) return;
				InternetAddress[] addresses = arrayList.toArray(new InternetAddress[arrayList.size()]);
				mimeMsessage.setRecipients(RecipientType.TO, addresses);
			}

			MimeMultipart mp = new MimeMultipart("alternative");
			mimeMsessage.setContent(mp);

			// create plain text part
			if(StringUtils.isNotBlank(plainText)){
				BodyPart mimeBodyPart = new MimeBodyPart();
				mimeBodyPart.setText(plainText);
				mp.addBodyPart(mimeBodyPart);
			}
			
			// create html part
			if(StringUtils.isNotBlank(htmlText)){
				BodyPart mimeBodyPart1 = new MimeBodyPart();
				mimeBodyPart1.setContent(htmlText, "text/html");
				mp.addBodyPart(mimeBodyPart1);
			}
			
			for (DataSource dataSource : attchements) {
				// create the base for our message
				MimeBodyPart attachment = new MimeBodyPart();
				attachment.setDataHandler(new DataHandler(dataSource));
				attachment.setHeader("Content-Transfer-Encoding", "base64");
				mp.addBodyPart(attachment);
			}

			smtpSender.signAndSendMultipartMessage(privateKey, senderCertificate, sender, issuerCertificate, issuer, mp, mimeMsessage);
		} catch (AddressException e) {
			throw new IllegalStateException("Can not send message", e);
		} catch (MessagingException e) {
			throw new IllegalStateException("Can not send message", e);
		}
 	}

	@Override
	public void registerProcessor(MessageProcessor messageProcessor) {
		// TODO Auto-generated method stub

	}

}
