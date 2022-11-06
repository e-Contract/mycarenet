/*
 * Java MyCareNet Project.
 * Copyright (C) 2016-2022 e-Contract.be BV.
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

package test.integ.be.e_contract.mycarenet.tarification;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import java.util.List;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import be.e_contract.mycarenet.sts.Attribute;
import be.e_contract.mycarenet.sts.AttributeDesignator;
import be.e_contract.mycarenet.sts.EHealthSTSClient;
import be.e_contract.mycarenet.tarification.TarificationClient;
import be.e_contract.mycarenet.tarification.jaxb.mycarenet.commons.protocol.ObjectFactory;
import be.e_contract.mycarenet.tarification.jaxb.mycarenet.commons.protocol.SendRequestType;
import be.fedict.commons.eid.jca.BeIDKeyStoreParameter;
import be.fedict.commons.eid.jca.BeIDProvider;
import test.integ.be.e_contract.mycarenet.Config;

public class TarificationClientTest {

	static final Log LOG = LogFactory.getLog(TarificationClientTest.class);

	private Config config;

	@BeforeEach
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testTarificationConsultation() throws Exception {
		// STS
		EHealthSTSClient client = new EHealthSTSClient(
				"https://services-acpt.ehealth.fgov.be/IAM/Saml11TokenService/Legacy/v1");

		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		BeIDKeyStoreParameter beIDKeyStoreParameter = new BeIDKeyStoreParameter();
		beIDKeyStoreParameter.addPPDUName("digipass 870");
		beIDKeyStoreParameter.addPPDUName("digipass 875");
		beIDKeyStoreParameter.addPPDUName("digipass 920");
		keyStore.load(beIDKeyStoreParameter);
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey("Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore.getCertificate("Authentication");

		KeyStore eHealthKeyStore = KeyStore.getInstance("PKCS12");
		FileInputStream fileInputStream = new FileInputStream(this.config.getEHealthPKCS12Path());
		eHealthKeyStore.load(fileInputStream, this.config.getEHealthPKCS12Password().toCharArray());
		Enumeration<String> aliasesEnum = eHealthKeyStore.aliases();
		String alias = aliasesEnum.nextElement();
		X509Certificate eHealthCertificate = (X509Certificate) eHealthKeyStore.getCertificate(alias);
		PrivateKey eHealthPrivateKey = (PrivateKey) eHealthKeyStore.getKey(alias,
				this.config.getEHealthPKCS12Password().toCharArray());

		List<Attribute> attributes = new LinkedList<>();
		attributes.add(new Attribute("urn:be:fgov:identification-namespace",
				"urn:be:fgov:ehealth:1.0:certificateholder:person:ssin"));
		attributes.add(new Attribute("urn:be:fgov:identification-namespace", "urn:be:fgov:person:ssin"));

		List<AttributeDesignator> attributeDesignators = new LinkedList<>();
		attributeDesignators.add(new AttributeDesignator("urn:be:fgov:identification-namespace",
				"urn:be:fgov:ehealth:1.0:certificateholder:person:ssin"));
		attributeDesignators
				.add(new AttributeDesignator("urn:be:fgov:identification-namespace", "urn:be:fgov:person:ssin"));
		attributeDesignators.add(new AttributeDesignator("urn:be:fgov:certified-namespace:ehealth",
				"urn:be:fgov:person:ssin:nurse:boolean"));

		Element assertion = client.requestAssertion(authnCertificate, authnPrivateKey, eHealthCertificate,
				eHealthPrivateKey, attributes, attributeDesignators);

		assertNotNull(assertion);

		String assertionString = client.toString(assertion);

		// Tarification
		TarificationClient tarificationClient = new TarificationClient(
				"https://services-acpt.ehealth.fgov.be/MyCareNet/Tarification/v1");
		tarificationClient.setCredentials(eHealthPrivateKey, assertionString);

		ObjectFactory objectFactory = new ObjectFactory();
		SendRequestType sendRequest = objectFactory.createSendRequestType();

		DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
		GregorianCalendar issueInstantCal = new GregorianCalendar();
		DateTime issueInstantDateTime = new DateTime();
		issueInstantCal.setTime(issueInstantDateTime.toDate());
		XMLGregorianCalendar issueInstant = datatypeFactory.newXMLGregorianCalendar(issueInstantCal);
		sendRequest.setIssueInstant(issueInstant);

		// TODO...

		tarificationClient.tarificationConsultation(sendRequest);

	}
}
