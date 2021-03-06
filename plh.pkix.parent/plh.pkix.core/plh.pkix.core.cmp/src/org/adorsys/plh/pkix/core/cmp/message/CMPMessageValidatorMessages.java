package org.adorsys.plh.pkix.core.cmp.message;

public abstract class CMPMessageValidatorMessages {

	public static final String CMPMessageValidatorMessages_conformity_missingSender ="CMPMessageValidatorMessages.conformity.missingSender";		
	public static final String CMPMessageValidatorMessages_conformity_senderNotADirectoryName ="CMPMessageValidatorMessages.conformity.senderNotADirectoryName";		
	public static final String CMPMessageValidatorMessages_conformity_missingRecipient ="CMPMessageValidatorMessages.conformity.missingRecipient";		
	public static final String CMPMessageValidatorMessages_conformity_missingProtection ="CMPMessageValidatorMessages.conformity.missingProtection";		
	public static final String CMPMessageValidatorMessages_conformity_macProtectionNotSupported ="CMPMessageValidatorMessages.conformity.macProtectionNotSupported";		
	public static final String CMPMessageValidatorMessages_conformity_notCertificateSentWithMessage= "CMPMessageValidatorMessages.conformity.notCertificateSentWithMessage";

	public static final String CMPMessageValidatorMessages_conformity_senderNotMatchingCertificate= "CMPMessageValidatorMessages.certificate.senderNotMatchingCertificate";
	public static final String CMPMessageValidatorMessages_conformity_canNotParseMessageTime= "CMPMessageValidatorMessages.response.canNotParseMessageTime";
	public static final String CMPMessageValidatorMessages_conformity_missingMessageTime= "CMPMessageValidatorMessages.response.missingMessageTime";

	public static final String CMPMessageValidatorMessages_conformity_signatureNotValid= "CMPMessageValidatorMessages.conformity.signatureNotValid";

}
