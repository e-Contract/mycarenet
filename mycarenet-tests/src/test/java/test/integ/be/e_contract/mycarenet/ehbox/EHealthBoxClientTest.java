/*
 * Java MyCareNet Project.
 * Copyright (C) 2013 Frank Cornelis.
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

package test.integ.be.e_contract.mycarenet.ehbox;

import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import test.integ.be.e_contract.mycarenet.Config;
import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.ehbox.EHealthBoxClient;
import be.e_contract.mycarenet.sts.EHealthSTSClient;
import be.fedict.commons.eid.jca.BeIDProvider;

public class EHealthBoxClientTest {

	private static final Log LOG = LogFactory
			.getLog(EHealthBoxClientTest.class);

	private Config config;

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testGetBoxInfo() throws Exception {
		// STS
		EHealthSTSClient client = new EHealthSTSClient(
				"https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService");

		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey(
				"Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore
				.getCertificate("Authentication");

		KeyStore eHealthKeyStore = KeyStore.getInstance("PKCS12");
		FileInputStream fileInputStream = new FileInputStream(
				this.config.getEHealthPKCS12Path());
		eHealthKeyStore.load(fileInputStream, this.config
				.getEHealthPKCS12Password().toCharArray());
		Enumeration<String> aliasesEnum = eHealthKeyStore.aliases();
		String alias = aliasesEnum.nextElement();
		X509Certificate eHealthCertificate = (X509Certificate) eHealthKeyStore
				.getCertificate(alias);
		PrivateKey eHealthPrivateKey = (PrivateKey) eHealthKeyStore.getKey(
				alias, this.config.getEHealthPKCS12Password().toCharArray());

		Element assertion = client.requestAssertion(authnCertificate,
				authnPrivateKey, eHealthCertificate, eHealthPrivateKey);

		assertNotNull(assertion);

		String assertionString = client.toString(assertion);

		// eHealthBox
		EHealthBoxClient eHealthBoxClient = new EHealthBoxClient(
				"https://services-acpt.ehealth.fgov.be/ehBoxConsultation/v2");
		eHealthBoxClient.getBoxInfo(eHealthPrivateKey, assertionString);
	}

	@Test
	public void testGetBoxInfoViaDOM() throws Exception {
		// STS
		EHealthSTSClient client = new EHealthSTSClient(
				"https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService");

		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey(
				"Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore
				.getCertificate("Authentication");

		KeyStore eHealthKeyStore = KeyStore.getInstance("PKCS12");
		FileInputStream fileInputStream = new FileInputStream(
				this.config.getEHealthPKCS12Path());
		eHealthKeyStore.load(fileInputStream, this.config
				.getEHealthPKCS12Password().toCharArray());
		Enumeration<String> aliasesEnum = eHealthKeyStore.aliases();
		String alias = aliasesEnum.nextElement();
		X509Certificate eHealthCertificate = (X509Certificate) eHealthKeyStore
				.getCertificate(alias);
		PrivateKey eHealthPrivateKey = (PrivateKey) eHealthKeyStore.getKey(
				alias, this.config.getEHealthPKCS12Password().toCharArray());

		Element assertion = client.requestAssertion(authnCertificate,
				authnPrivateKey, eHealthCertificate, eHealthPrivateKey);

		assertNotNull(assertion);

		String request = "<ehbox:GetBoxInfoRequest xmlns:ehbox=\"urn:be:fgov:ehealth:ehbox:consultation:protocol:v2\"/>";
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document requestDocument = documentBuilder.parse(new InputSource(
				new StringReader(request)));
		Element requestElement = requestDocument.getDocumentElement();

		// eHealthBox
		EHealthBoxClient eHealthBoxClient = new EHealthBoxClient(
				"https://services-acpt.ehealth.fgov.be/ehBoxConsultation/v2");
		eHealthBoxClient.invoke(requestElement, eHealthPrivateKey,
				toString(assertion));
	}

	@Test
	public void testGetBoxInfoViaString() throws Exception {
		// STS
		EHealthSTSClient client = new EHealthSTSClient(
				"https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService");

		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey(
				"Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore
				.getCertificate("Authentication");

		KeyStore eHealthKeyStore = KeyStore.getInstance("PKCS12");
		FileInputStream fileInputStream = new FileInputStream(
				this.config.getEHealthPKCS12Path());
		eHealthKeyStore.load(fileInputStream, this.config
				.getEHealthPKCS12Password().toCharArray());
		Enumeration<String> aliasesEnum = eHealthKeyStore.aliases();
		String alias = aliasesEnum.nextElement();
		X509Certificate eHealthCertificate = (X509Certificate) eHealthKeyStore
				.getCertificate(alias);
		PrivateKey eHealthPrivateKey = (PrivateKey) eHealthKeyStore.getKey(
				alias, this.config.getEHealthPKCS12Password().toCharArray());

		Element assertion = client.requestAssertion(authnCertificate,
				authnPrivateKey, eHealthCertificate, eHealthPrivateKey);

		assertNotNull(assertion);

		String request = "<ehbox:GetBoxInfoRequest xmlns:ehbox=\"urn:be:fgov:ehealth:ehbox:consultation:protocol:v2\"/>";

		// eHealthBox
		EHealthBoxClient eHealthBoxClient = new EHealthBoxClient(
				"https://services-acpt.ehealth.fgov.be/ehBoxConsultation/v2");
		String result = eHealthBoxClient.invoke(request, eHealthPrivateKey,
				toString(assertion));
		LOG.debug("result: " + result);
	}

	@Test
	public void testGetBoxInfoSelfSigned() throws Exception {
		// STS
		EHealthSTSClient client = new EHealthSTSClient(
				"https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService");

		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey(
				"Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore
				.getCertificate("Authentication");

		SessionKey sessionKey = new SessionKey(2048);
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusHours(24);
		sessionKey.setValidity(notBefore.toDate(), notAfter.toDate());
		X509Certificate eHealthCertificate = sessionKey.getCertificate();
		PrivateKey eHealthPrivateKey = sessionKey.getPrivate();

		Element assertionElement = client.requestAssertion(authnCertificate,
				authnPrivateKey, eHealthCertificate, eHealthPrivateKey);

		assertNotNull(assertionElement);

		String assertionString = client.toString(assertionElement);

		// eHealthBox
		EHealthBoxClient eHealthBoxClient = new EHealthBoxClient(
				"https://services-acpt.ehealth.fgov.be/ehBoxConsultation/v2");
		eHealthBoxClient.getBoxInfo(eHealthPrivateKey, assertionString);
	}

	private String toString(Node node) throws Exception {
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		StringWriter stringWriter = new StringWriter();
		transformer.transform(new DOMSource(node), new StreamResult(
				stringWriter));
		return stringWriter.toString();
	}
}
