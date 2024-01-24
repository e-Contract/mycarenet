/*
 * Java MyCareNet Project.
 * Copyright (C) 2013-2023 e-Contract.be BV.
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
package be.e_contract.mycarenet.ehealth.common;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.xml.crypto.dsig.Reference;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.SOAPConstants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.e_contract.mycarenet.common.WSSecurityCrypto;

/**
 * WS-Security JAX-WS SOAP handler implementation for eHealth web services that
 * are secured using the eHealth STS SAML assertion and holder-of-key.
 *
 * @author Frank Cornelis
 *
 */
public class WSSecuritySOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Logger LOGGER = LoggerFactory.getLogger(WSSecuritySOAPHandler.class);

	private PrivateKey privateKey;

	private String samlAssertion;

	private final DocumentBuilder documentBuilder;

	public WSSecuritySOAPHandler() {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		try {
			this.documentBuilder = documentBuilderFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			throw new RuntimeException("DOM error: " + e.getMessage(), e);
		}
	}

	/**
	 * Sets the eHealth holder-of-key private key.
	 *
	 * @param privateKey
	 */
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * Sets the eHealth STS SAML assertion.
	 *
	 * @param samlAssertion
	 */
	public void setAssertion(String samlAssertion) {
		this.samlAssertion = samlAssertion;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (false == outboundProperty) {
			return true;
		}
		try {
			handleOutboundMessage(context);
		} catch (Exception e) {
			LOGGER.error("outbound exception: " + e.getMessage(), e);
			throw new ProtocolException(e);
		}
		return true;
	}

	private void handleOutboundMessage(SOAPMessageContext context)
			throws WSSecurityException, SAXException, IOException {
		LOGGER.debug("adding WS-Security header");
		if (null == this.samlAssertion) {
			LOGGER.error("missing SAML assertion");
			return;
		}
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		WSSecHeader wsSecHeader = new WSSecHeader(soapPart);
		Element securityHeaderElement = wsSecHeader.insertSecurityHeader();

		WSSecTimestamp wsSecTimeStamp = new WSSecTimestamp(wsSecHeader);
		wsSecTimeStamp.setTimeToLive(60);
		wsSecTimeStamp.build();

		Document assertionDocument = this.documentBuilder.parse(new InputSource(new StringReader(this.samlAssertion)));
		Element assertionElement = assertionDocument.getDocumentElement();
		String assertionId = assertionElement.getAttribute("AssertionID");
		Element importedAssertionElement = (Element) soapPart.importNode(assertionElement, true);
		securityHeaderElement.appendChild(importedAssertionElement);

		WSSecSignature wsSecSignature = new WSSecSignature(wsSecHeader);
		if (this.privateKey.getAlgorithm().equals("EC")) {
			wsSecSignature.setSignatureAlgorithm(WSConstants.ECDSA_SHA256);
		} else {
			wsSecSignature.setSignatureAlgorithm(WSConstants.RSA_SHA256);
		}
		wsSecSignature.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
		wsSecSignature.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
		wsSecSignature.setCustomTokenValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
		wsSecSignature.setCustomTokenId(assertionId);
		Crypto crypto = new WSSecurityCrypto(this.privateKey, null);
		wsSecSignature.prepare(crypto);

		Vector<WSEncryptionPart> signParts = new Vector<>();
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(soapPart.getDocumentElement());
		signParts.add(new WSEncryptionPart(soapConstants.getBodyQName().getLocalPart(), soapConstants.getEnvelopeURI(),
				"Content"));
		signParts.add(new WSEncryptionPart(wsSecTimeStamp.getId()));
		List<Reference> referenceList = wsSecSignature.addReferencesToSign(signParts);
		wsSecSignature.computeSignature(referenceList, false, null);
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		return false;
	}

	@Override
	public void close(MessageContext context) {
	}

	@Override
	public Set<QName> getHeaders() {
		return null;
	}
}
