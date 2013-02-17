package org.adorsys.plh.pkix.core.test.utils;

import org.adorsys.plh.pkix.core.utils.GeneralNameHolder;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.Assert;
import org.junit.Test;

public class GeneralNameHolderTest {

	@Test
	public void test() {
		X500Name dirName = X500NameHelper.makeX500Name("francis", "francis@plhtest.biz");
		String name = "francis@plhtest.biz";
		GeneralName generalName =new GeneralName(dirName);
		Assert.assertFalse(name.equals(generalName.toString()));
		GeneralNameHolder generalNameHolder = new GeneralNameHolder(generalName);
		Assert.assertEquals(dirName, generalNameHolder.getX500Name());
	}

}
