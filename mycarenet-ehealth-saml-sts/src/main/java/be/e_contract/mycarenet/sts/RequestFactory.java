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

package be.e_contract.mycarenet.sts;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.UUID;

import javax.security.auth.x500.X500Principal;
import javax.xml.namespace.QName;

import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Attribute;
import org.opensaml.saml1.core.AttributeDesignator;
import org.opensaml.saml1.core.AttributeQuery;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.AttributeValue;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.ConfirmationMethod;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectConfirmation;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class RequestFactory {

	private static final XMLObjectBuilderFactory xmlObjectBuilderFactory;
	private static final XSStringBuilder stringBuilder;

	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException(e);
		}
		xmlObjectBuilderFactory = Configuration.getBuilderFactory();
		stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory()
				.getBuilder(XSString.TYPE_NAME);
	}

	private <T extends SAMLObject> T buildObject(QName name, Class<T> clazz) {
		SAMLObjectBuilder samlObjectBuilder = (SAMLObjectBuilder) xmlObjectBuilderFactory
				.getBuilder(name);
		return (T) samlObjectBuilder.buildObject();
	}

	private Request createRequest() {
		Request request = buildObject(Request.DEFAULT_ELEMENT_NAME,
				Request.class);
		request.setIssueInstant(new DateTime());
		request.setID("request_"
				+ UUID.randomUUID().toString().replace("-", ""));
		request.setVersion(SAMLVersion.VERSION_11);
		return request;
	}

	private AttributeQuery createQuery(Request request) {
		AttributeQuery query = buildObject(AttributeQuery.DEFAULT_ELEMENT_NAME,
				AttributeQuery.class);
		request.setQuery(query);
		return query;
	}

	private Subject createRequestSubject(AttributeQuery query,
			X509Certificate authnCertificate) {
		Subject subject = createSubject(query);
		addNameIdentifier(subject, authnCertificate);
		return subject;
	}

	private NameIdentifier createNameIdentifier(Subject subject) {
		NameIdentifier name = buildObject(NameIdentifier.DEFAULT_ELEMENT_NAME,
				NameIdentifier.class);
		subject.setNameIdentifier(name);
		return name;
	}

	private NameIdentifier addNameIdentifier(Subject subject,
			X509Certificate authnCertificate) {
		NameIdentifier name = createNameIdentifier(subject);
		name.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");
		name.setNameQualifier(getPrincipalName(authnCertificate
				.getIssuerX500Principal()));
		name.setNameIdentifier(getPrincipalName(authnCertificate
				.getSubjectX500Principal()));
		return name;
	}

	private String getPrincipalName(X500Principal principal) {
		return principal.getName("RFC1779");
	}

	private Subject createSubject(AttributeQuery query) {
		Subject subject = buildObject(Subject.DEFAULT_ELEMENT_NAME,
				Subject.class);
		query.setSubject(subject);
		return subject;
	}

	private ConfirmationMethod createConfirmationMethod(
			SubjectConfirmation subjectConfirmation) {
		ConfirmationMethod method = buildObject(
				ConfirmationMethod.DEFAULT_ELEMENT_NAME,
				ConfirmationMethod.class);
		subjectConfirmation.getConfirmationMethods().add(method);
		return method;
	}

	private KeyInfo createKeyInfo(SubjectConfirmation subjectConfirmation,
			X509Certificate authnCertificate) {
		KeyInfo keyInfo = createKeyInfo(authnCertificate);
		subjectConfirmation.setKeyInfo(keyInfo);
		return keyInfo;
	}

	private KeyInfo createKeyInfo(X509Certificate certificate) {
		KeyInfo keyInfo = (KeyInfo) Configuration.getBuilderFactory()
				.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME)
				.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
		X509Data data = (X509Data) Configuration.getBuilderFactory()
				.getBuilder(X509Data.DEFAULT_ELEMENT_NAME)
				.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
		org.opensaml.xml.signature.X509Certificate cert = (org.opensaml.xml.signature.X509Certificate) Configuration
				.getBuilderFactory()
				.getBuilder(
						org.opensaml.xml.signature.X509Certificate.DEFAULT_ELEMENT_NAME)
				.buildObject(
						org.opensaml.xml.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
		try {
			cert.setValue(Base64.encode(certificate.getEncoded()));
		} catch (CertificateEncodingException e) {
			throw new RuntimeException(e);
		}
		data.getX509Certificates().add(cert);
		keyInfo.getX509Datas().add(data);
		return keyInfo;
	}

	private SubjectConfirmation createSubjectConfirmation(Subject subject,
			X509Certificate hokCertificate) {
		SubjectConfirmation subjectConfirmation = buildObject(
				SubjectConfirmation.DEFAULT_ELEMENT_NAME,
				SubjectConfirmation.class);
		subject.setSubjectConfirmation(subjectConfirmation);
		ConfirmationMethod method = createConfirmationMethod(subjectConfirmation);
		method.setConfirmationMethod("urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");
		createKeyInfo(subjectConfirmation, hokCertificate);
		return subjectConfirmation;
	}

	private Conditions createConditions(Assertion assertion) {
		Conditions conditions = buildObject(Conditions.DEFAULT_ELEMENT_NAME,
				Conditions.class);
		assertion.setConditions(conditions);
		return conditions;
	}

	private Assertion createAssertion(SubjectConfirmation subjectConfirmation,
			X509Certificate authnCertificate) {
		XSAnyBuilder proxyBuilder = new XSAnyBuilder();
		QName oqname = new QName("urn:oasis:names:tc:SAML:1.0:assertion",
				"SubjectConfirmationData", "saml1");
		XSAny confirmData = (XSAny) proxyBuilder.buildObject(oqname);
		subjectConfirmation.setSubjectConfirmationData(confirmData);

		Assertion assertion = buildObject(Assertion.DEFAULT_ELEMENT_NAME,
				Assertion.class);
		assertion.setID("assertion_"
				+ UUID.randomUUID().toString().replace("-", ""));
		assertion.setIssueInstant(new DateTime());

		confirmData.getUnknownXMLObjects().add(assertion);
		assertion.setIssuer(getPrincipalName(authnCertificate
				.getSubjectX500Principal()));
		Conditions conditions = createConditions(assertion);
		DateTime now = new DateTime();
		DateTime inOneHourFromNow = now.plusHours(12);
		conditions.setNotBefore(now);
		conditions.setNotOnOrAfter(inOneHourFromNow);
		return assertion;
	}

	private AttributeStatement createAttributeStatement(Assertion assertion) {
		AttributeStatement attributeStatement = buildObject(
				AttributeStatement.DEFAULT_ELEMENT_NAME,
				AttributeStatement.class);
		assertion.getAttributeStatements().add(attributeStatement);
		return attributeStatement;
	}

	private Subject createAssertionSubject(AttributeStatement stmt,
			X509Certificate authnCertificate) {
		Subject subject = buildObject(Subject.DEFAULT_ELEMENT_NAME,
				Subject.class);
		addNameIdentifier(subject, authnCertificate);
		stmt.setSubject(subject);
		return subject;
	}

	private Attribute createAttribute(AttributeStatement stmt) {
		Attribute attribute = buildObject(Attribute.DEFAULT_ELEMENT_NAME,
				Attribute.class);
		stmt.getAttributes().add(attribute);
		return attribute;
	}

	private XSString buildString(QName name) {
		return (XSString) stringBuilder.buildObject(name, XSString.TYPE_NAME);
	}

	private XSString createAttributeValue(Attribute attr) {
		XSString val = buildString(AttributeValue.DEFAULT_ELEMENT_NAME);
		attr.getAttributeValues().add(val);
		return val;
	}

	private Attribute createAttribute(AttributeStatement stmt, String name,
			String namespace, String value) {
		Attribute attr = createAttribute(stmt);
		attr.setAttributeName(name);
		attr.setAttributeNamespace(namespace);
		XSString attrVal = createAttributeValue(attr);
		attrVal.setValue(value);
		return attr;
	}

	private String getUserId(X509Certificate signingCertificate) {
		X500Principal userPrincipal = signingCertificate
				.getSubjectX500Principal();
		String name = userPrincipal.toString();
		int serialNumberBeginIdx = name.indexOf("SERIALNUMBER=");
		if (-1 == serialNumberBeginIdx) {
			throw new SecurityException("SERIALNUMBER not found in X509 CN");
		}
		int serialNumberValueBeginIdx = serialNumberBeginIdx
				+ "SERIALNUMBER=".length();
		int serialNumberValueEndIdx = name.indexOf(",",
				serialNumberValueBeginIdx);
		if (-1 == serialNumberValueEndIdx) {
			serialNumberValueEndIdx = name.length();
		}
		String userId = name.substring(serialNumberValueBeginIdx,
				serialNumberValueEndIdx);
		return userId;
	}

	private void createAttributes(AttributeStatement stmt,
			X509Certificate authnCertificate) {
		createAttribute(stmt,
				"urn:be:fgov:ehealth:1.0:certificateholder:person:ssin",
				"urn:be:fgov:identification-namespace",
				getUserId(authnCertificate));
	}

	private AttributeDesignator createAttributeDesignator(AttributeQuery query) {
		AttributeDesignator designator = buildObject(
				AttributeDesignator.DEFAULT_ELEMENT_NAME,
				AttributeDesignator.class);
		query.getAttributeDesignators().add(designator);
		return designator;
	}

	private AttributeDesignator createAttributeDesignator(AttributeQuery query,
			String name, String namespace) {
		AttributeDesignator designator = createAttributeDesignator(query);
		designator.setAttributeName(name);
		designator.setAttributeNamespace(namespace);
		return designator;
	}

	private void createAttributeDesignators(AttributeQuery query) {
		createAttributeDesignator(query,
				"urn:be:fgov:ehealth:1.0:certificateholder:person:ssin",
				"urn:be:fgov:identification-namespace");
	}

	private BasicX509Credential getSigningCredentials(PrivateKey hokPrivateKey,
			X509Certificate hokCertificate) {
		BasicX509Credential c = new BasicX509Credential();
		c.setPrivateKey(hokPrivateKey);
		c.setPublicKey(hokCertificate.getPublicKey());
		c.setEntityCertificate(hokCertificate);
		return c;
	}

	private Signature createSignature(Request request,
			PrivateKey hokPrivateKey, X509Certificate hokCertificate) {
		Signature sig = (Signature) xmlObjectBuilderFactory.getBuilder(
				Signature.DEFAULT_ELEMENT_NAME).buildObject(
				Signature.DEFAULT_ELEMENT_NAME);
		request.setSignature(sig);
		sig.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
		sig.setCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
		sig.setSigningCredential(getSigningCredentials(hokPrivateKey,
				hokCertificate));
		KeyInfo keyInfo = createKeyInfo(hokCertificate);
		sig.setKeyInfo(keyInfo);
		return sig;
	}

	public Element createRequest(X509Certificate authnCertificate,
			PrivateKey hokPrivateKey, X509Certificate hokCertificate) {
		Request request = createRequest();
		AttributeQuery attributeQuery = createQuery(request);
		Subject subjectRequest = createRequestSubject(attributeQuery,
				authnCertificate);
		SubjectConfirmation subjectConfirmation = createSubjectConfirmation(
				subjectRequest, hokCertificate);
		Assertion assertion = createAssertion(subjectConfirmation,
				authnCertificate);
		AttributeStatement stmt = createAttributeStatement(assertion);
		createAssertionSubject(stmt, authnCertificate);
		createAttributes(stmt, authnCertificate);
		createAttributeDesignators(attributeQuery);

		Signature sig = createSignature(request, hokPrivateKey, hokCertificate);

		Marshaller marshaller = Configuration.getMarshallerFactory()
				.getMarshaller(request);
		Element requestElement;
		try {
			requestElement = marshaller.marshall(request);
		} catch (MarshallingException e) {
			throw new RuntimeException(e);
		}
		try {
			Signer.signObject(sig);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
		return requestElement;
	}
}
