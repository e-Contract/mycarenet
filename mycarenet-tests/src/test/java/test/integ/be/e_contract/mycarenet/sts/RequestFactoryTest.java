/*
 * Java MyCareNet Project.
 * Copyright (C) 2013 e-Contract.be BVBA.
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

package test.integ.be.e_contract.mycarenet.sts;

import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Element;

import test.integ.be.e_contract.mycarenet.Config;
import be.e_contract.mycarenet.sts.Attribute;
import be.e_contract.mycarenet.sts.AttributeDesignator;
import be.e_contract.mycarenet.sts.RequestFactory;
import be.fedict.commons.eid.jca.BeIDProvider;

public class RequestFactoryTest {

	private static final Log LOG = LogFactory.getLog(RequestFactoryTest.class);

	private Config config;

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testCreateRequest() throws Exception {
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

		RequestFactory requestFactory = new RequestFactory();

		List<Attribute> attributes = new LinkedList<Attribute>();
		attributes.add(new Attribute("urn:be:fgov:identification-namespace",
				"urn:be:fgov:ehealth:1.0:certificateholder:person:ssin"));
		attributes.add(new Attribute("urn:be:fgov:identification-namespace",
				"urn:be:fgov:person:ssin"));

		List<AttributeDesignator> attributeDesignators = new LinkedList<AttributeDesignator>();
		attributeDesignators.add(new AttributeDesignator(
				"urn:be:fgov:identification-namespace",
				"urn:be:fgov:ehealth:1.0:certificateholder:person:ssin"));
		attributeDesignators.add(new AttributeDesignator(
				"urn:be:fgov:identification-namespace",
				"urn:be:fgov:person:ssin"));
		attributeDesignators.add(new AttributeDesignator(
				"urn:be:fgov:certified-namespace:ehealth",
				"urn:be:fgov:person:ssin:nurse:boolean"));

		Element requestElement = requestFactory.createRequest(authnCertificate,
				eHealthPrivateKey, eHealthCertificate, attributes,
				attributeDesignators);

		assertNotNull(requestElement);

		LOG.debug("request: " + toString(requestElement));
	}

	private String toString(Element element) throws TransformerException {
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(element), new StreamResult(writer));
		return writer.toString();
	}
}
