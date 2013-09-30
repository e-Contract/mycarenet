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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.joda.time.DateTime;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.e_contract.mycarenet.jaxb.saml.AssertionType;
import be.e_contract.mycarenet.jaxb.saml.AttributeDesignatorType;
import be.e_contract.mycarenet.jaxb.saml.AttributeStatementType;
import be.e_contract.mycarenet.jaxb.saml.AttributeType;
import be.e_contract.mycarenet.jaxb.saml.ConditionsType;
import be.e_contract.mycarenet.jaxb.saml.NameIdentifierType;
import be.e_contract.mycarenet.jaxb.saml.ObjectFactory;
import be.e_contract.mycarenet.jaxb.saml.SubjectConfirmationType;
import be.e_contract.mycarenet.jaxb.saml.SubjectType;
import be.e_contract.mycarenet.jaxb.samlp.AttributeQueryType;
import be.e_contract.mycarenet.jaxb.samlp.RequestType;
import be.e_contract.mycarenet.jaxb.xmldsig.KeyInfoType;
import be.e_contract.mycarenet.jaxb.xmldsig.X509DataType;

/**
 * Factory for SAML Request.
 * <p/>
 * We don't use OpenSAML here as this conflicts with the JBoss CXF runtime.
 * 
 * @author Frank Cornelis
 * 
 */
public class RequestFactory {

	private final ObjectFactory samlObjectFactory;
	private final be.e_contract.mycarenet.jaxb.samlp.ObjectFactory samlpObjectFactory;
	private final be.e_contract.mycarenet.jaxb.xmldsig.ObjectFactory xmldsigObjectFactory;
	private final Marshaller marshaller;
	private final DocumentBuilder documentBuilder;
	private final DatatypeFactory datatypeFactory;

	public RequestFactory() {
		this.samlObjectFactory = new ObjectFactory();
		this.samlpObjectFactory = new be.e_contract.mycarenet.jaxb.samlp.ObjectFactory();
		this.xmldsigObjectFactory = new be.e_contract.mycarenet.jaxb.xmldsig.ObjectFactory();

		try {
			JAXBContext jaxbContext = JAXBContext
					.newInstance(be.e_contract.mycarenet.jaxb.samlp.ObjectFactory.class);
			this.marshaller = jaxbContext.createMarshaller();
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		try {
			this.documentBuilder = documentBuilderFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			throw new RuntimeException("DOM error: " + e.getMessage(), e);
		}

		try {
			this.datatypeFactory = DatatypeFactory.newInstance();
		} catch (DatatypeConfigurationException e) {
			throw new RuntimeException(e);
		}
	}

	private RequestType createRequest() {
		RequestType request = this.samlpObjectFactory.createRequestType();
		String requestId = "request-" + UUID.randomUUID().toString();
		request.setRequestID(requestId);
		request.setMajorVersion(BigInteger.ONE);
		request.setMinorVersion(BigInteger.ONE);
		DateTime now = new DateTime();
		request.setIssueInstant(toXMLGregorianCalendar(now));
		return request;
	}

	private AttributeQueryType createAttributeQuery(RequestType request) {
		AttributeQueryType attributeQuery = this.samlpObjectFactory
				.createAttributeQueryType();
		request.setAttributeQuery(attributeQuery);
		return attributeQuery;
	}

	private SubjectType createSubject(AttributeQueryType attributeQuery) {
		SubjectType subject = this.samlObjectFactory.createSubjectType();
		attributeQuery.setSubject(subject);
		return subject;
	}

	private NameIdentifierType createNameIdentifier(SubjectType subject,
			X509Certificate authnCertificate) {
		NameIdentifierType nameIdentifier = this.samlObjectFactory
				.createNameIdentifierType();
		nameIdentifier
				.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");
		nameIdentifier.setNameQualifier(authnCertificate
				.getIssuerX500Principal().getName("RFC1779"));
		nameIdentifier.setValue(authnCertificate.getSubjectX500Principal()
				.getName("RFC1779"));
		subject.getContent().add(
				this.samlObjectFactory.createNameIdentifier(nameIdentifier));
		return nameIdentifier;
	}

	private SubjectConfirmationType createSubjectConfirmation(
			SubjectType subject) {
		SubjectConfirmationType subjectConfirmation = this.samlObjectFactory
				.createSubjectConfirmationType();
		subjectConfirmation.getConfirmationMethod().add(
				"urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");
		subject.getContent().add(
				this.samlObjectFactory
						.createSubjectConfirmation(subjectConfirmation));
		return subjectConfirmation;
	}

	private XMLGregorianCalendar toXMLGregorianCalendar(DateTime date) {
		GregorianCalendar calendar = new GregorianCalendar();
		calendar.setTime(date.toDate());
		calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
		return this.datatypeFactory.newXMLGregorianCalendar(calendar);
	}

	private void createSubject(AttributeStatementType attributeStatement,
			X509Certificate authnCertificate) {
		SubjectType subject = this.samlObjectFactory.createSubjectType();
		attributeStatement.setSubject(subject);
		createNameIdentifier(subject, authnCertificate);
	}

	private void createAttribute(AttributeStatementType attributeStatement,
			String namespace, String name, String value) {
		AttributeType attribute = this.samlObjectFactory.createAttributeType();
		attributeStatement.getAttribute().add(attribute);
		attribute.setAttributeNamespace(namespace);
		attribute.setAttributeName(name);
		attribute.getAttributeValue().add(value);
	}

	private void createAttributeStatement(AssertionType assertion,
			X509Certificate authnCertificate, List<Attribute> attributes) {
		AttributeStatementType attributeStatement = this.samlObjectFactory
				.createAttributeStatementType();
		assertion.getStatementOrSubjectStatementOrAuthenticationStatement()
				.add(attributeStatement);
		createSubject(attributeStatement, authnCertificate);

		for (Attribute attribute : attributes) {
			String attributeValue;
			if (attribute.isInjectNRNValue()) {
				attributeValue = getUserIdentifier(authnCertificate);
			} else {
				attributeValue = attribute.getValue();
			}
			createAttribute(attributeStatement, attribute.getNamespace(),
					attribute.getName(), attributeValue);
		}
	}

	private String getUserIdentifier(X509Certificate certificate) {
		X500Principal userPrincipal = certificate.getSubjectX500Principal();
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

	private void createConditions(AssertionType assertion) {
		ConditionsType conditions = this.samlObjectFactory
				.createConditionsType();
		DateTime notBefore = new DateTime();
		conditions.setNotBefore(toXMLGregorianCalendar(notBefore));
		DateTime notAfter = notBefore.plusHours(24);
		conditions.setNotOnOrAfter(toXMLGregorianCalendar(notAfter));
		assertion.setConditions(conditions);
	}

	private AssertionType createAssertion(X509Certificate authnCertificate,
			List<Attribute> attributes) {
		AssertionType assertion = this.samlObjectFactory.createAssertionType();
		String assertionId = "assertion-" + UUID.randomUUID().toString();
		assertion.setAssertionID(assertionId);
		assertion.setMajorVersion(BigInteger.ONE);
		assertion.setMinorVersion(BigInteger.ONE);
		DateTime now = new DateTime();
		assertion.setIssueInstant(toXMLGregorianCalendar(now));
		assertion.setIssuer(authnCertificate.getSubjectX500Principal().getName(
				"RFC1779"));
		createConditions(assertion);
		createAttributeStatement(assertion, authnCertificate, attributes);
		return assertion;
	}

	private void createSubjectConfirmationData(
			SubjectConfirmationType subjectConfirmation,
			X509Certificate authnCertificate, List<Attribute> attributes) {
		Document document = this.documentBuilder.newDocument();
		document.appendChild(document.createElementNS(
				"urn:oasis:names:tc:SAML:1.0:assertion",
				"SubjectConfirmationData"));
		AssertionType assertion = createAssertion(authnCertificate, attributes);
		try {
			this.marshaller.marshal(
					this.samlObjectFactory.createAssertion(assertion),
					document.getDocumentElement());
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
		subjectConfirmation.setSubjectConfirmationData(document
				.getDocumentElement());
	}

	private void createX509Data(KeyInfoType keyInfo,
			X509Certificate hokCertificate) {
		X509DataType x509Data = this.xmldsigObjectFactory.createX509DataType();
		keyInfo.getContent().add(
				this.xmldsigObjectFactory.createX509Data(x509Data));
		try {
			x509Data.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(
					this.xmldsigObjectFactory
							.createX509DataTypeX509Certificate(hokCertificate
									.getEncoded()));
		} catch (CertificateEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	private void createKeyInfo(SubjectConfirmationType subjectConfirmation,
			X509Certificate hokCertificate) {
		KeyInfoType keyInfo = this.xmldsigObjectFactory.createKeyInfoType();
		subjectConfirmation.setKeyInfo(keyInfo);
		createX509Data(keyInfo, hokCertificate);
	}

	private void createAttributeDesignator(AttributeQueryType attributeQuery,
			String namespace, String name) {
		AttributeDesignatorType attributeDesignator = this.samlObjectFactory
				.createAttributeDesignatorType();
		attributeDesignator.setAttributeNamespace(namespace);
		attributeDesignator.setAttributeName(name);
		attributeQuery.getAttributeDesignator().add(attributeDesignator);
	}

	private void signRequest(Element requestElement, PrivateKey privateKey,
			X509Certificate certificate) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, MarshalException,
			XMLSignatureException {
		DOMSignContext domSignContext = new DOMSignContext(privateKey,
				requestElement, requestElement.getFirstChild());
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance("DOM");

		String requestId = requestElement.getAttribute("RequestID");
		requestElement.setIdAttribute("RequestID", true);

		List<Transform> transforms = new LinkedList<Transform>();
		transforms.add(xmlSignatureFactory.newTransform(Transform.ENVELOPED,
				(TransformParameterSpec) null));
		transforms.add(xmlSignatureFactory.newTransform(
				CanonicalizationMethod.EXCLUSIVE,
				(C14NMethodParameterSpec) null));
		Reference reference = xmlSignatureFactory.newReference("#" + requestId,
				xmlSignatureFactory.newDigestMethod(DigestMethod.SHA1, null),
				transforms, null, null);

		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(
				xmlSignatureFactory.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE,
						(C14NMethodParameterSpec) null), xmlSignatureFactory
						.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
				Collections.singletonList(reference));

		KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections
				.singletonList(keyInfoFactory.newX509Data(Collections
						.singletonList(certificate))));

		XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(
				signedInfo, keyInfo);
		xmlSignature.sign(domSignContext);
	}

	public Element createRequest(X509Certificate authnCertificate,
			PrivateKey hokPrivateKey, X509Certificate hokCertificate,
			List<Attribute> attributes,
			List<AttributeDesignator> attributeDesignators) {
		RequestType request = createRequest();
		AttributeQueryType attributeQuery = createAttributeQuery(request);
		SubjectType subject = createSubject(attributeQuery);
		createNameIdentifier(subject, authnCertificate);
		SubjectConfirmationType subjectConfirmation = createSubjectConfirmation(subject);
		createSubjectConfirmationData(subjectConfirmation, authnCertificate,
				attributes);
		createKeyInfo(subjectConfirmation, hokCertificate);

		for (AttributeDesignator attributeDesignator : attributeDesignators) {
			createAttributeDesignator(attributeQuery,
					attributeDesignator.getNamespace(),
					attributeDesignator.getName());
		}

		Element requestElement = toDOM(request);
		try {
			signRequest(requestElement, hokPrivateKey, hokCertificate);
		} catch (Exception e) {
			throw new RuntimeException(
					"XML signature error: " + e.getMessage(), e);
		}
		return requestElement;
	}

	private Element toDOM(RequestType request) {
		Document document = this.documentBuilder.newDocument();
		try {
			this.marshaller.marshal(
					this.samlpObjectFactory.createRequest(request), document);
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
		return document.getDocumentElement();
	}
}
