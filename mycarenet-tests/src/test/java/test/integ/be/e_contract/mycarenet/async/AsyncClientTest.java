/*
 * Java MyCareNet Project.
 * Copyright (C) 2012-2015 e-Contract.be BVBA.
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

package test.integ.be.e_contract.mycarenet.async;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import test.integ.be.e_contract.mycarenet.Config;
import be.e_contract.mycarenet.async.AsyncClient;
import be.e_contract.mycarenet.async.PackageLicenseKey;
import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.xkms2.XKMS2Client;
import be.fedict.commons.eid.jca.BeIDKeyStoreParameter;
import be.fedict.commons.eid.jca.BeIDProvider;

public class AsyncClientTest {

	private static final Log LOG = LogFactory.getLog(AsyncClientTest.class);

	@Test
	public void testEcho() throws Exception {
		// setup
		String xkms2Location = "https://pilot.mycarenet.be/mycarenet-ws/care-provider/xkms2";
		XKMS2Client xkms2Client = new XKMS2Client(xkms2Location);
		SessionKey sessionKey = new SessionKey();

		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");

		BeIDKeyStoreParameter beIDKeyStoreParameter = new BeIDKeyStoreParameter();
		beIDKeyStoreParameter.addPPDUName("digipass 870");
		beIDKeyStoreParameter.addPPDUName("digipass 875");
		beIDKeyStoreParameter.addPPDUName("digipass 920");
		keyStore.load(beIDKeyStoreParameter);

		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey(
				"Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore
				.getCertificate("Authentication");

		// operate
		xkms2Client.registerSessionKey(sessionKey, authnPrivateKey,
				authnCertificate);

		// verify
		assertTrue(sessionKey.isValid());

		try {
			// setup
			Config config = new Config();
			PackageLicenseKey packageLicenseKey = config.getPackageLicenseKey();
			LOG.debug("package license key username: "
					+ packageLicenseKey.getUsername());
			LOG.debug("package license key password: "
					+ packageLicenseKey.getPassword());
			AsyncClient asyncClient = new AsyncClient(
					"https://pilot.mycarenet.be/mycarenet-ws/care-provider/async",
					sessionKey, packageLicenseKey);
			String message = "hello world";

			// operate
			String result;
			try {
				result = asyncClient.echo(message);
			} finally {
				LOG.debug("payload: " + asyncClient.getPayload());
			}

			// verify
			assertEquals(result, message);
		} finally {
			// operate
			xkms2Client.revokeSessionKey(sessionKey, authnPrivateKey,
					authnCertificate);

			// verify
			assertFalse(sessionKey.isValid());
		}
	}

}
