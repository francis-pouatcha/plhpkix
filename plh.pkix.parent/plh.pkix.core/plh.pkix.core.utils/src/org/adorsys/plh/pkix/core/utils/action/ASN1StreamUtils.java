package org.adorsys.plh.pkix.core.utils.action;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Object;

public abstract class ASN1StreamUtils {
	
	public static void writeTo(ASN1Object asn1Object, OutputStream outputStream) {
		try {
			byte[] data = asn1Object.getEncoded();
			IOUtils.write(data, outputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	public static byte[] readFrom(InputStream inputStream) {
		try {
			return IOUtils.toByteArray(inputStream);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

}
