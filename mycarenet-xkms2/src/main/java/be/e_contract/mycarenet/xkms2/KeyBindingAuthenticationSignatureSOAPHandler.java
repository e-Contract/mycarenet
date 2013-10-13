/*
 * Java MyCareNet Project.
 * Copyright (C) 2012 Frank Cornelis.
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

package be.e_contract.mycarenet.xkms2;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
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
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
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

/**
 * XKMS 2.0 key binding authentication signature JAX-WS SOAP handler
 * implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class KeyBindingAuthenticationSignatureSOAPHandler implements
		SOAPHandler<SOAPMessageContext> {

	private static final Log LOG = LogFactory
			.getLog(KeyBindingAuthenticationSignatureSOAPHandler.class);

	private PrivateKey authnPrivateKey;

	private X509Certificate authnCertificate;

	private String prototypeKeyBindingId;

	private String revokeKeyBindingId;

	private String referenceUri;

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (false == outboundProperty) {
			return true;
		}
		LOG.debug("adding key binding authentication signature");
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		String requestElementName;
		if (null != this.prototypeKeyBindingId) {
			requestElementName = "RegisterRequest";
			this.referenceUri = "#" + this.prototypeKeyBindingId;
		} else if (null != this.revokeKeyBindingId) {
			requestElementName = "RevokeRequest";
			this.referenceUri = "#" + this.revokeKeyBindingId;
		} else {
			LOG.error("missing key binding id");
			return false;
		}
		NodeList requestNodeList = soapPart.getElementsByTagNameNS(
				XKMS2ServiceFactory.XKMS2_NAMESPACE, requestElementName);
		Element requestElement = (Element) requestNodeList.item(0);
		if (null == requestElement) {
			LOG.error("request element not present");
			return false;
		}
		Document xkmsDocument;
		try {
			xkmsDocument = copyDocument(requestElement);
		} catch (ParserConfigurationException e) {
			LOG.error("error copying XKMS request: " + e.getMessage(), e);
			return false;
		}

		NodeList keyBindingAuthenticationNodeList = xkmsDocument
				.getElementsByTagNameNS(XKMS2ServiceFactory.XKMS2_NAMESPACE,
						"KeyBindingAuthentication");
		Element keyBindingAuthenticationElement = (Element) keyBindingAuthenticationNodeList
				.item(0);
		try {
			prepareDocument(xkmsDocument);
			addSignature(keyBindingAuthenticationElement);
		} catch (Exception e) {
			LOG.error("error adding authn signature: " + e.getMessage(), e);
			return false;
		}

		Node signatureNode = soapPart.importNode(
				keyBindingAuthenticationElement.getFirstChild(), true);

		keyBindingAuthenticationNodeList = soapPart
				.getElementsByTagNameNS(XKMS2ServiceFactory.XKMS2_NAMESPACE,
						"KeyBindingAuthentication");
		keyBindingAuthenticationElement = (Element) keyBindingAuthenticationNodeList
				.item(0);
		keyBindingAuthenticationElement.appendChild(signatureNode);
		return true;
	}

	private void prepareDocument(Document xkmsDocument) {
		Element prototypeElement = xkmsDocument
				.getElementById(this.prototypeKeyBindingId);
		if (null == prototypeElement) {
			LOG.warn("Prototype element not found via Id");
			prototypeElement = (Element) xkmsDocument.getElementsByTagNameNS(
					XKMS2ServiceFactory.XKMS2_NAMESPACE, "PrototypeKeyBinding")
					.item(0);
			if (null == prototypeElement) {
				prototypeElement = (Element) xkmsDocument
						.getElementsByTagNameNS(
								XKMS2ServiceFactory.XKMS2_NAMESPACE,
								"RevokeKeyBinding").item(0);
			}
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
				this.authnPrivateKey, parentElement);
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance("DOM");

		Reference reference = xmlSignatureFactory.newReference(
				this.referenceUri, xmlSignatureFactory.newDigestMethod(
						DigestMethod.SHA1, null), Collections
						.singletonList(xmlSignatureFactory.newTransform(
								CanonicalizationMethod.EXCLUSIVE,
								(TransformParameterSpec) null)), null, null);

		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(
				xmlSignatureFactory.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE,
						(C14NMethodParameterSpec) null), xmlSignatureFactory
						.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
				Collections.singletonList(reference));

		KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections
				.singletonList(keyInfoFactory.newX509Data(Collections
						.singletonList(this.authnCertificate))));

		XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(
				signedInfo, keyInfo);
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

	/**
	 * Sets the signer identity.
	 * 
	 * @param authnPrivateKey
	 *            the eID authentication private key.
	 * @param authnCertificate
	 *            the eID authentication certificate.
	 */
	public void setSigner(PrivateKey authnPrivateKey,
			X509Certificate authnCertificate) {
		this.authnPrivateKey = authnPrivateKey;
		this.authnCertificate = authnCertificate;
	}

	public void setPrototypeKeyBindingId(String prototypeKeyBindingId) {
		this.prototypeKeyBindingId = prototypeKeyBindingId;
		this.revokeKeyBindingId = null;
	}

	public void setRevokeKeyBindingId(String revokeKeyBindingId) {
		this.revokeKeyBindingId = revokeKeyBindingId;
		this.prototypeKeyBindingId = null;
	}
}
