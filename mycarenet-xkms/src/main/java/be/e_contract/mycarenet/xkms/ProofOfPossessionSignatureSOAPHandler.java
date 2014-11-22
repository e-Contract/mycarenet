/*
 * Java MyCareNet Project.
 * Copyright (C) 2012 e-Contract.be BVBA.
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

package be.e_contract.mycarenet.xkms;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Set;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import be.e_contract.mycarenet.common.SessionKey;

/**
 * Proof of possession signature JAX-WS SOAP handler implementation for
 * MyCareNet XKMS version 1.0.
 * 
 * @author Frank Cornelis
 * 
 */
public class ProofOfPossessionSignatureSOAPHandler implements
		SOAPHandler<SOAPMessageContext> {

	private static final Log LOG = LogFactory
			.getLog(ProofOfPossessionSignatureSOAPHandler.class);

	private static final String XKMS_NAMESPACE = "http://www.xkms.org/schema/xkms-2001-01-20";

	private SessionKey sessionKey;

	private String prototypeKeyBindingId;

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		if (null == this.sessionKey) {
			return true;
		}
		if (null == this.prototypeKeyBindingId) {
			return true;
		}

		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (false == outboundProperty) {
			return true;
		}
		LOG.debug("adding proof of possession signature");
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		NodeList registerRequestNodeList = soapPart.getElementsByTagNameNS(
				XKMS_NAMESPACE, "Register");
		Element registerRequestElement = (Element) registerRequestNodeList
				.item(0);
		Document xkmsDocument;
		try {
			xkmsDocument = copyDocument(registerRequestElement);
		} catch (ParserConfigurationException e) {
			LOG.error("error copying XKMS request: " + e.getMessage(), e);
			return false;
		}

		NodeList proofOfPossessionNodeList = xkmsDocument
				.getElementsByTagNameNS(XKMS_NAMESPACE, "ProofOfPossession");
		Element proofOfPossessionElement = (Element) proofOfPossessionNodeList
				.item(0);
		try {
			prepareDocument(xkmsDocument);
			addSignature(proofOfPossessionElement);
		} catch (Exception e) {
			LOG.error("error adding proof signature: " + e.getMessage(), e);
			return false;
		}
		Node signatureNode = soapPart.importNode(
				proofOfPossessionElement.getFirstChild(), true);

		proofOfPossessionNodeList = soapPart.getElementsByTagNameNS(
				XKMS_NAMESPACE, "ProofOfPossession");
		proofOfPossessionElement = (Element) proofOfPossessionNodeList.item(0);
		proofOfPossessionElement.appendChild(signatureNode);
		return true;
	}

	private void prepareDocument(Document xkmsDocument) {
		Element prototypeElement = xkmsDocument
				.getElementById(this.prototypeKeyBindingId);
		if (null == prototypeElement) {
			LOG.warn("Prototype element not found via Id");
			prototypeElement = (Element) xkmsDocument.getElementsByTagNameNS(
					XKMS_NAMESPACE, "Prototype").item(0);
			prototypeElement.setIdAttribute("Id", true);
		}
	}

	private Document copyDocument(Element element)
			throws ParserConfigurationException {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.newDocument();
		Node importedNode = document.importNode(element, true);
		document.appendChild(importedNode);
		return document;
	}

	private void addSignature(Element parentElement)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, MarshalException,
			XMLSignatureException {
		DOMSignContext domSignContext = new DOMSignContext(
				this.sessionKey.getPrivate(), parentElement);
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance("DOM");

		Reference reference = xmlSignatureFactory.newReference("#"
				+ this.prototypeKeyBindingId, xmlSignatureFactory
				.newDigestMethod(DigestMethod.SHA1, null), Collections
				.singletonList(xmlSignatureFactory.newTransform(
						CanonicalizationMethod.EXCLUSIVE,
						(TransformParameterSpec) null)), null, null);

		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(
				xmlSignatureFactory.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE,
						(C14NMethodParameterSpec) null), xmlSignatureFactory
						.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
				Collections.singletonList(reference));

		XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(
				signedInfo, null);
		xmlSignature.sign(domSignContext);
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

	public void setSessionKey(SessionKey sessionKey) {
		this.sessionKey = sessionKey;
	}

	public void setPrototypeId(String prototypeKeyBindingId) {
		this.prototypeKeyBindingId = prototypeKeyBindingId;
	}
}
