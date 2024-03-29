/*
 * Java MyCareNet Project.
 * Copyright (C) 2013-2022 e-Contract.be BV.
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

import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

import javax.xml.bind.DatatypeConverter;
import javax.xml.namespace.QName;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.Binding;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;
import javax.xml.ws.handler.Handler;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.jaxws.sts.EHealthSamlStsService;

/**
 * The eHealth STS client.
 * 
 * @author Frank Cornelis
 * 
 */
public class EHealthSTSClient {

	public static final String NAME_IDENTIFIER_X509_SUBJECT_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";

	public static final String CONFIRMATION_METHOD_HOLDER_OF_KEY = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";

	private static final Logger LOGGER = LoggerFactory.getLogger(EHealthSTSClient.class);

	private final Dispatch<Source> dispatch;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	/**
	 * Main constructor.
	 * 
	 * @param location the URL of the eHealth STS web service.
	 */
	public EHealthSTSClient(String location) {
		EHealthSamlStsService service = EHealthSamlStsServiceFactory.newInstance();

		QName portQName = new QName("urn:be:ehealth:saml:sts:1.0", "EHealthSamlStsPort");
		this.dispatch = service.createDispatch(portQName, Source.class, Service.Mode.PAYLOAD);

		this.dispatch.getRequestContext().put(Dispatch.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = dispatch.getBinding();
		@SuppressWarnings("rawtypes")
		List<Handler> handlerChain = binding.getHandlerChain();
		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		handlerChain.add(this.wsSecuritySOAPHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);
	}

	/**
	 * Requests an eHealth SAML assertion from the eHealth STS.
	 * 
	 * @param authnCertificate     the eID authentication certificate.
	 * @param authnPrivateKey      the eID authentication private key.
	 * @param hokCertificate       the eHealth holder-of-key authentication
	 *                             certificate.
	 * @param hokPrivateKey        the eHealth holder-of-key authentication private
	 *                             key.
	 * @param attributes           the identity attributes.
	 * @param attributeDesignators the required attributes.
	 * @return the SAML assertion as DOM element.
	 * @throws Exception           in case something goes wrong.
	 * @throws EHealthSTSException in case the STS returned no SAML assertion.
	 */
	public Element requestAssertion(X509Certificate authnCertificate, PrivateKey authnPrivateKey,
			X509Certificate hokCertificate, PrivateKey hokPrivateKey, List<Attribute> attributes,
			List<AttributeDesignator> attributeDesignators) throws Exception {
		this.wsSecuritySOAPHandler.setCertificate(authnCertificate);
		this.wsSecuritySOAPHandler.setPrivateKey(authnPrivateKey);

		RequestFactory requestFactory = new RequestFactory();
		Element requestElement = requestFactory.createRequest(authnCertificate, hokPrivateKey, hokCertificate,
				attributes, attributeDesignators);

		Source responseSource = this.dispatch.invoke(new DOMSource(requestElement));

		Element responseElement = toElement(responseSource);

		NodeList assertionNodeList = responseElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion",
				"Assertion");
		if (assertionNodeList.getLength() == 0) {
			LOGGER.error("no assertion in response");
			NodeList statusNodeList = responseElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:protocol",
					"Status");
			if (statusNodeList.getLength() == 1) {
				Element statusElement = (Element) statusNodeList.item(0);
				throw new EHealthSTSException(statusElement);
			}
			return null;
		}
		return (Element) assertionNodeList.item(0);
	}

	private Element toElement(Source source) {
		if (source instanceof DOMSource) {
			DOMSource domSource = (DOMSource) source;
			return (Element) domSource.getNode();
		}
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		}
		DOMResult domResult = new DOMResult();
		try {
			transformer.transform(source, domResult);
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
		Document document = (Document) domResult.getNode();
		return (Element) document.getDocumentElement();
	}

	/**
	 * Returns the value of the NotOnOrAfter element within the given SAML
	 * assertion.
	 * 
	 * @param assertionElement
	 * @return
	 */
	public DateTime getNotAfter(Element assertionElement) {
		NodeList conditionsNodeList = assertionElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion",
				"Conditions");
		Element conditionsElement = (Element) conditionsNodeList.item(0);
		String notOnOrAfterAttributeValue = conditionsElement.getAttribute("NotOnOrAfter");
		Calendar calendar = DatatypeConverter.parseDateTime(notOnOrAfterAttributeValue);
		return new DateTime(calendar.getTime());
	}

	/**
	 * Converts a given DOM element to a String.
	 * 
	 * @param element
	 * @return
	 */
	public String toString(Element element) {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		}
		StringWriter stringWriter = new StringWriter();
		try {
			transformer.transform(new DOMSource(element), new StreamResult(stringWriter));
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
		return stringWriter.toString();
	}
}
