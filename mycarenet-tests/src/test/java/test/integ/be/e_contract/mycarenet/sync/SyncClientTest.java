/*
 * Java MyCareNet Project.
 * Copyright (C) 2012-2022 e-Contract.be BV.
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

package test.integ.be.e_contract.mycarenet.sync;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.e_contract.mycarenet.async.PackageLicenseKey;
import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.jaxb.sync.ObjectFactory;
import be.e_contract.mycarenet.jaxb.sync.XmlDocumentWrapperType;
import be.e_contract.mycarenet.sync.SyncClient;
import be.e_contract.mycarenet.xkms2.XKMS2Client;
import be.fedict.commons.eid.jca.BeIDKeyStoreParameter;
import be.fedict.commons.eid.jca.BeIDProvider;
import test.integ.be.e_contract.mycarenet.Config;

public class SyncClientTest {

	private static final Log LOG = LogFactory.getLog(SyncClientTest.class);

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
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey("Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore.getCertificate("Authentication");

		// operate
		xkms2Client.registerSessionKey(sessionKey, authnPrivateKey, authnCertificate);

		// verify
		assertTrue(sessionKey.isValid());

		try {
			// setup
			Config config = new Config();
			PackageLicenseKey packageLicenseKey = config.getPackageLicenseKey();
			LOG.debug("package license key username: " + packageLicenseKey.getUsername());
			LOG.debug("package license key password: " + packageLicenseKey.getPassword());
			SyncClient syncClient = new SyncClient("https://pilot.mycarenet.be/services/care-provider/sync", sessionKey,
					packageLicenseKey);

			ObjectFactory objectFactory = new ObjectFactory();
			XmlDocumentWrapperType request = objectFactory.createXmlDocumentWrapperType();
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
			DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
			Document document = documentBuilder.newDocument();
			Element element = document.createElement("test");
			request.setAny(element);
			request.setLang("en");
			// operate
			XmlDocumentWrapperType result;
			try {
				result = syncClient.echo(request);
			} finally {
				LOG.debug("payload: " + syncClient.getPayload());
			}

			// verify
			assertEquals(result.getAny().getNodeName(), "test");
		} finally {
			// operate
			xkms2Client.revokeSessionKey(sessionKey, authnPrivateKey, authnCertificate);

			// verify
			assertFalse(sessionKey.isValid());
		}
	}

	@Test
	public void testEchoViaInvoke() throws Exception {
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
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey("Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore.getCertificate("Authentication");

		// operate
		xkms2Client.registerSessionKey(sessionKey, authnPrivateKey, authnCertificate);

		// verify
		assertTrue(sessionKey.isValid());

		try {
			// setup
			Config config = new Config();
			PackageLicenseKey packageLicenseKey = config.getPackageLicenseKey();
			LOG.debug("package license key username: " + packageLicenseKey.getUsername());
			LOG.debug("package license key password: " + packageLicenseKey.getPassword());
			SyncClient syncClient = new SyncClient("https://pilot.mycarenet.be/services/care-provider/sync", sessionKey,
					packageLicenseKey);

			String result = syncClient
					.invoke("<EchoRequest xmlns=\"urn:be:cin:mycarenet:1.0:sync:types\" xml:lang=\"en\">" + "<test/>"
							+ "</EchoRequest>");

			// verify
			LOG.debug("result: " + result);
		} finally {
			// operate
			xkms2Client.revokeSessionKey(sessionKey, authnPrivateKey, authnCertificate);

			// verify
			assertFalse(sessionKey.isValid());
		}
	}
}
