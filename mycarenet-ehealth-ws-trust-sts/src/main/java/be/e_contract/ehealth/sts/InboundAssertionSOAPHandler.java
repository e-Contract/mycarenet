/*
 * Java MyCareNet Project.
 * Copyright (C) 2023 e-Contract.be BV.
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
package be.e_contract.ehealth.sts;

import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * JAX-WS SOAP Handler to capture inbound SAML Assertions.
 *
 * @author Frank Cornelis
 */
public class InboundAssertionSOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Logger LOGGER = LoggerFactory.getLogger(InboundAssertionSOAPHandler.class);

	private Element assertion;

	public Element getAssertion() {
		return this.assertion;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (outboundProperty) {
			return true;
		}
		try {
			handleInboundMessage(context);
		} catch (Exception e) {
			LOGGER.error("error: " + e.getMessage(), e);
			throw new ProtocolException(e);
		}
		return true;
	}

	private void handleInboundMessage(SOAPMessageContext context) throws Exception {
		NodeList assertionNodeList = context.getMessage().getSOAPBody()
				.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Assertion");
		if (assertionNodeList.getLength() == 0) {
			this.assertion = null;
			return;
		}
		Node assertionNode = assertionNodeList.item(0);
		DocumentBuilder documentBuilder = createSecureDocumentBuilder();
		Document document = documentBuilder.newDocument();
		Element importedElement = (Element) document.importNode(assertionNode, true);
		document.appendChild(importedElement);
		this.assertion = importedElement;
	}

	private DocumentBuilder createSecureDocumentBuilder() throws ParserConfigurationException {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
		documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
		documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
		documentBuilderFactory.setXIncludeAware(false);
		documentBuilderFactory.setExpandEntityReferences(false);
		DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		return documentBuilder;
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	@Override
	public void close(MessageContext context) {
	}

	@Override
	public Set<QName> getHeaders() {
		return null;
	}
}
