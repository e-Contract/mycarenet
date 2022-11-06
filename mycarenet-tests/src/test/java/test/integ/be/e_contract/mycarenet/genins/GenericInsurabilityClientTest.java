/*
 * Java MyCareNet Project.
 * Copyright (C) 2014-2022 e-Contract.be BV.
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

package test.integ.be.e_contract.mycarenet.genins;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.FileInputStream;
import java.math.BigDecimal;
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
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.joda.time.DateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.e_contract.mycarenet.async.PackageLicenseKey;
import be.e_contract.mycarenet.genins.GenericInsurabilityClient;
import be.e_contract.mycarenet.genins.jaxb.core.CareProviderType;
import be.e_contract.mycarenet.genins.jaxb.core.CareReceiverIdType;
import be.e_contract.mycarenet.genins.jaxb.core.CommonInputType;
import be.e_contract.mycarenet.genins.jaxb.core.IdType;
import be.e_contract.mycarenet.genins.jaxb.core.InsurabilityContactTypeType;
import be.e_contract.mycarenet.genins.jaxb.core.InsurabilityRequestDetailType;
import be.e_contract.mycarenet.genins.jaxb.core.InsurabilityRequestTypeType;
import be.e_contract.mycarenet.genins.jaxb.core.LicenseType;
import be.e_contract.mycarenet.genins.jaxb.core.NihiiType;
import be.e_contract.mycarenet.genins.jaxb.core.OriginType;
import be.e_contract.mycarenet.genins.jaxb.core.PackageType;
import be.e_contract.mycarenet.genins.jaxb.core.PeriodType;
import be.e_contract.mycarenet.genins.jaxb.core.RecordCommonInputType;
import be.e_contract.mycarenet.genins.jaxb.core.RequestType;
import be.e_contract.mycarenet.genins.jaxb.core.SingleInsurabilityRequestType;
import be.e_contract.mycarenet.genins.jaxb.core.ValueRefString;
import be.e_contract.mycarenet.genins.jaxb.protocol.GetInsurabilityAsXmlOrFlatRequestType;
import be.e_contract.mycarenet.genins.jaxb.protocol.ObjectFactory;
import be.e_contract.mycarenet.sts.Attribute;
import be.e_contract.mycarenet.sts.AttributeDesignator;
import be.e_contract.mycarenet.sts.EHealthSTSClient;
import be.fedict.commons.eid.jca.BeIDKeyStoreParameter;
import be.fedict.commons.eid.jca.BeIDProvider;
import test.integ.be.e_contract.mycarenet.Config;

public class GenericInsurabilityClientTest {

	static final Log LOG = LogFactory.getLog(GenericInsurabilityClientTest.class);

	private Config config;

	@BeforeEach
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testSTSNurse() throws Exception {
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
		LOG.debug("SAML assertion: " + assertionString);
	}

	@Test
	public void testSTSDoctor() throws Exception {
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
				"urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11"));
		attributeDesignators.add(new AttributeDesignator("urn:be:fgov:certified-namespace:ehealth",
				"urn:be:fgov:person:ssin:doctor:boolean"));

		Element assertion = client.requestAssertion(authnCertificate, authnPrivateKey, eHealthCertificate,
				eHealthPrivateKey, attributes, attributeDesignators);

		assertNotNull(assertion);

		String assertionString = client.toString(assertion);
		LOG.debug("SAML assertion: " + assertionString);
	}

	@Test
	public void testInvoke() throws Exception {
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
				"urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11"));
		attributeDesignators.add(new AttributeDesignator("urn:be:fgov:certified-namespace:ehealth",
				"urn:be:fgov:person:ssin:doctor:boolean"));

		Element assertion = client.requestAssertion(authnCertificate, authnPrivateKey, eHealthCertificate,
				eHealthPrivateKey, attributes, attributeDesignators);

		assertNotNull(assertion);

		String assertionString = client.toString(assertion);

		// String location =
		// "https://services-int.ehealth.fgov.be/GenericInsurability/v1";
		String location = "https://services-acpt.ehealth.fgov.be/GenericInsurability/v1";
		GenericInsurabilityClient genInsClient = new GenericInsurabilityClient(location);
		genInsClient.setCredentials(eHealthPrivateKey, assertionString);

		ObjectFactory objectFactory = new ObjectFactory();
		GetInsurabilityAsXmlOrFlatRequestType body = objectFactory.createGetInsurabilityAsXmlOrFlatRequestType();

		be.e_contract.mycarenet.genins.jaxb.core.ObjectFactory coreObjectFactory = new be.e_contract.mycarenet.genins.jaxb.core.ObjectFactory();
		CommonInputType commonInput = coreObjectFactory.createCommonInputType();
		body.setCommonInput(commonInput);

		RequestType request = coreObjectFactory.createRequestType();
		request.setIsTest(true);
		commonInput.setRequest(request);

		OriginType origin = coreObjectFactory.createOriginType();
		commonInput.setOrigin(origin);
		PackageType packageObject = coreObjectFactory.createPackageType();
		origin.setPackage(packageObject);
		LicenseType license = coreObjectFactory.createLicenseType();
		packageObject.setLicense(license);
		PackageLicenseKey packageLicenseKey = this.config.getPackageLicenseKey();
		license.setUsername(packageLicenseKey.getUsername());
		license.setPassword(packageLicenseKey.getPassword());

		Element namespaceElement = assertion.getOwnerDocument().createElement("ns");
		namespaceElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:saml",
				"urn:oasis:names:tc:SAML:1.0:assertion");
		Node nihiiNode = XPathAPI.selectSingleNode(assertion,
				"saml:AttributeStatement/saml:Attribute[@AttributeName='urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11']/saml:AttributeValue/text()",
				namespaceElement);
		String myNihii = nihiiNode.getTextContent();
		LOG.debug("NIHII: " + myNihii);
		Node ssinNode = XPathAPI.selectSingleNode(assertion,
				"saml:AttributeStatement/saml:Attribute[@AttributeName='urn:be:fgov:person:ssin']/saml:AttributeValue/text()",
				namespaceElement);
		String mySsin = ssinNode.getTextContent();

		CareProviderType careProvider = coreObjectFactory.createCareProviderType();
		origin.setCareProvider(careProvider);
		NihiiType nihii = coreObjectFactory.createNihiiType();
		careProvider.setNihii(nihii);
		nihii.setQuality("doctor");
		ValueRefString nihiiValue = coreObjectFactory.createValueRefString();
		nihii.setValue(nihiiValue);
		nihiiValue.setValue(myNihii);
		IdType physicalPerson = coreObjectFactory.createIdType();
		careProvider.setPhysicalPerson(physicalPerson);
		ValueRefString ssinValue = coreObjectFactory.createValueRefString();
		physicalPerson.setSsin(ssinValue);
		ssinValue.setValue(mySsin);

		commonInput.setInputReference("PRIG1234567890");
		RecordCommonInputType recordCommonInput = coreObjectFactory.createRecordCommonInputType();
		body.setRecordCommonInput(recordCommonInput);
		recordCommonInput.setInputReference(new BigDecimal("1234567890123"));

		SingleInsurabilityRequestType singleInsurabilityRequest = coreObjectFactory
				.createSingleInsurabilityRequestType();
		body.setRequest(singleInsurabilityRequest);
		CareReceiverIdType careReceiverId = coreObjectFactory.createCareReceiverIdType();
		singleInsurabilityRequest.setCareReceiverId(careReceiverId);
		careReceiverId.setInss(mySsin);
		InsurabilityRequestDetailType insurabilityRequestDetail = coreObjectFactory
				.createInsurabilityRequestDetailType();
		singleInsurabilityRequest.setInsurabilityRequestDetail(insurabilityRequestDetail);
		InsurabilityRequestTypeType insurabilityRequestType = InsurabilityRequestTypeType.INFORMATION;
		insurabilityRequestDetail.setInsurabilityRequestType(insurabilityRequestType);
		PeriodType period = coreObjectFactory.createPeriodType();
		insurabilityRequestDetail.setPeriod(period);
		DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
		GregorianCalendar periodStartCal = new GregorianCalendar();
		DateTime periodStartDateTime = new DateTime();
		periodStartCal.setTime(periodStartDateTime.toDate());
		XMLGregorianCalendar periodStart = datatypeFactory.newXMLGregorianCalendar(periodStartCal);
		period.setPeriodStart(periodStart);
		DateTime periodEndDateTime = periodStartDateTime;
		GregorianCalendar periodEndCal = new GregorianCalendar();
		periodEndCal.setTime(periodEndDateTime.toDate());
		XMLGregorianCalendar periodEnd = datatypeFactory.newXMLGregorianCalendar(periodEndCal);
		period.setPeriodEnd(periodEnd);
		insurabilityRequestDetail.setInsurabilityContactType(InsurabilityContactTypeType.HOSPITALIZED_FOR_DAY);

		genInsClient.getInsurability(body);
	}
}
