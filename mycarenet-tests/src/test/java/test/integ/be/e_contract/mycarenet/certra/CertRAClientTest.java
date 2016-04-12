/*
 * Java MyCareNet Project.
 * Copyright (C) 2016 e-Contract.be BVBA.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package test.integ.be.e_contract.mycarenet.certra;

import static org.junit.Assert.assertNotNull;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import be.e_contract.mycarenet.certra.CertRAClient;
import be.fedict.commons.eid.jca.BeIDKeyStoreParameter;
import be.fedict.commons.eid.jca.BeIDProvider;

public class CertRAClientTest {

	@BeforeClass
	public static void beforeClass() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new BeIDProvider());
	}

	@Test
	public void testGetRevocableCertificates() throws Exception {
		KeyStore keyStore = KeyStore.getInstance("BeID");
		BeIDKeyStoreParameter beIDKeyStoreParameter = new BeIDKeyStoreParameter();
		beIDKeyStoreParameter.addPPDUName("digipass 870");
		beIDKeyStoreParameter.addPPDUName("digipass 875");
		beIDKeyStoreParameter.addPPDUName("digipass 920");
		keyStore.load(beIDKeyStoreParameter);
		PrivateKey signPrivateKey = (PrivateKey) keyStore.getKey("Signature", null);
		assertNotNull(signPrivateKey);
		X509Certificate signCertificate = (X509Certificate) keyStore.getCertificate("Signature");
		assertNotNull(signCertificate);

		CertRAClient client = new CertRAClient("https://services-acpt.ehealth.fgov.be/CertRa/v1");
		client.getRevocableCertificates(signPrivateKey, signCertificate);
	}
}
