package org.adorys.plh.pkix.core.test.cmp.utils;

import org.adorys.plh.pkix.core.cmp.utils.GeneralNameHolder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.Assert;
import org.junit.Test;

public class GeneralNameHolderTest {

	@Test
	public void test() {
		String name = "CN=Test sender";
		X500Name dirName = new X500Name(name);
		GeneralName generalName =new GeneralName(dirName);
		Assert.assertFalse(name.equals(generalName.toString()));
		GeneralNameHolder generalNameHolder = new GeneralNameHolder(generalName);
		Assert.assertEquals(name, generalNameHolder.getUtf8Name());
	}

}
