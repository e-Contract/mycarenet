/*
 * Java MyCareNet Project.
 * Copyright (C) 2013-2015 e-Contract.be BVBA.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.util.WSSecurityUtil;
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

	private static final Log LOG = LogFactory
			.getLog(WSSecuritySOAPHandler.class);

	private PrivateKey privateKey;

	private String samlAssertion;

	private final DocumentBuilder documentBuilder;

	public WSSecuritySOAPHandler() {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
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
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (false == outboundProperty) {
			return true;
		}
		try {
			handleOutboundMessage(context);
		} catch (Exception e) {
			LOG.error("outbound exception: " + e.getMessage(), e);
			throw new ProtocolException(e);
		}
		return true;
	}

	private void handleOutboundMessage(SOAPMessageContext context)
			throws WSSecurityException, SAXException, IOException {
		LOG.debug("adding WS-Security header");
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		WSSecHeader wsSecHeader = new WSSecHeader();
		wsSecHeader.insertSecurityHeader(soapPart);

		WSSecTimestamp wsSecTimeStamp = new WSSecTimestamp();
		wsSecTimeStamp.setTimeToLive(60);
		wsSecTimeStamp.build(soapPart, wsSecHeader);

		Document assertionDocument = this.documentBuilder
				.parse(new InputSource(new StringReader(this.samlAssertion)));
		Element assertionElement = assertionDocument.getDocumentElement();
		String assertionId = assertionElement.getAttribute("AssertionID");
		Element importedAssertionElement = (Element) soapPart.importNode(
				assertionElement, true);
		Element securityHeaderElement = wsSecHeader.getSecurityHeader();
		securityHeaderElement.appendChild(importedAssertionElement);

		WSSecSignature wsSecSignature = new WSSecSignature();
		wsSecSignature.setSignatureAlgorithm(WSConstants.RSA);
		wsSecSignature.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
		wsSecSignature
				.setCustomTokenValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
		wsSecSignature.setCustomTokenId(assertionId);
		Crypto crypto = new WSSecurityCrypto(this.privateKey, null);
		wsSecSignature.prepare(soapPart, crypto, wsSecHeader);
		Vector<WSEncryptionPart> signParts = new Vector<>();
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(soapPart
				.getDocumentElement());
		signParts.add(new WSEncryptionPart(soapConstants.getBodyQName()
				.getLocalPart(), soapConstants.getEnvelopeURI(), "Content"));
		signParts.add(new WSEncryptionPart(wsSecTimeStamp.getId()));
		List<Reference> referenceList = wsSecSignature.addReferencesToSign(
				signParts, wsSecHeader);
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