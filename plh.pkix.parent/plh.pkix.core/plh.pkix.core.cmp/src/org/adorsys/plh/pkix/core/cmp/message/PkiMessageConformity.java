package org.adorsys.plh.pkix.core.cmp.message;

import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;

/**
 * Generic message processor. Load and verify the message for formal correctness
 * and integrity. Throw an {@link IllegalStateException} if the message is
 * malformed of modified.
 * 
 * @author francis
 * 
 */
public class PkiMessageConformity {

	public static ProtectedPKIMessage check(GeneralPKIMessage generalPKIMessage) {

		PKIHeader pkiHeader = generalPKIMessage.getHeader();

		GeneralName sender = pkiHeader.getSender();
		if (sender == null)
			throw new IllegalStateException("Missing sender");

		GeneralName recipient = pkiHeader.getRecipient();
		if (recipient == null)
			throw new IllegalStateException("Missing recipient");

		if (!generalPKIMessage.hasProtection())
			throw new IllegalStateException("Missing protection");

		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(
				generalPKIMessage);
		if (protectedPKIMessage.hasPasswordBasedMacProtection())
			throw new UnsupportedOperationException(
					"Mac based protection not supported");
		return protectedPKIMessage;
	}
}
