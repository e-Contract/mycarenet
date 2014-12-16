/*
 * Java MyCareNet Project.
 * Copyright (C) 2012 e-Contract.be BVBA.
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

package test.integ.be.e_contract.mycarenet.cxf;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.spi.Provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.junit.Test;

import test.integ.be.e_contract.mycarenet.Config;
import be.e_contract.mycarenet.async.AsyncClient;
import be.e_contract.mycarenet.async.PackageLicenseKey;
import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.xkms.XKMSClient;
import be.e_contract.mycarenet.xkms2.XKMS2Client;
import be.fedict.commons.eid.jca.BeIDProvider;

public class CXFTest {

	private static final Log LOG = LogFactory.getLog(CXFTest.class);

	@Test
	public void testProvider() {
		Provider provider = Provider.provider();
		LOG.debug("provider class: " + provider.getClass().getName());
		assertEquals("org.apache.cxf.jaxws22.spi.ProviderImpl", provider
				.getClass().getName());
	}

	@Test
	public void testRegisterRevokeSessionKey() throws Exception {
		// setup
		String xkms2Location = "https://pilot.mycarenet.be/mycarenet-ws/care-provider/xkms2";
		XKMS2Client xkms2Client = new XKMS2Client(xkms2Location);
		SessionKey sessionKey = new SessionKey();

		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey(
				"Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore
				.getCertificate("Authentication");

		// operate
		xkms2Client.registerSessionKey(sessionKey, authnPrivateKey,
				authnCertificate);

		// verify
		assertTrue(sessionKey.isValid());

		// operate
		xkms2Client.revokeSessionKey(sessionKey, authnPrivateKey,
				authnCertificate);

		// verify
		assertFalse(sessionKey.isValid());
	}

	@Test
	public void testRegisterViaXKMS2RevokeViaXKMS1() throws Exception {
		// setup
		String xkms2Location = "https://pilot.mycarenet.be/mycarenet-ws/care-provider/xkms2";
		XKMS2Client xkms2Client = new XKMS2Client(xkms2Location);
		SessionKey sessionKey = new SessionKey();

		String xkmsLocation = "https://pilot.mycarenet.be/mycarenet-ws/care-provider/xkms";
		XKMSClient xkmsClient = new XKMSClient(xkmsLocation);

		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey(
				"Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore
				.getCertificate("Authentication");

		// operate
		xkms2Client.registerSessionKey(sessionKey, authnPrivateKey,
				authnCertificate);

		// verify
		assertTrue(sessionKey.isValid());

		// operate
		xkmsClient.revokeSessionKey(sessionKey);

		// verify
		assertFalse(sessionKey.isValid());
	}

	@Test
	public void testEcho() throws Exception {
		// setup
		String xkms2Location = "https://pilot.mycarenet.be/mycarenet-ws/care-provider/xkms2";
		XKMS2Client xkms2Client = new XKMS2Client(xkms2Location);
		SessionKey sessionKey = new SessionKey();

		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
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

			BindingProvider bindingProvider = asyncClient.getBindingProvider();
			Client client = ClientProxy.getClient(bindingProvider);
			HTTPConduit http = (HTTPConduit) client.getConduit();
			HTTPClientPolicy httpClientPolicy = new HTTPClientPolicy();
			httpClientPolicy.setConnectionTimeout(36000); // ms
			httpClientPolicy.setReceiveTimeout(36000); // ms
			http.setClient(httpClientPolicy);

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
			XKMSClient xkmsClient = new XKMSClient(
					"https://pilot.mycarenet.be/mycarenet-ws/care-provider/xkms");
			xkmsClient.revokeSessionKey(sessionKey);

			// verify
			assertFalse(sessionKey.isValid());
		}
	}
}
