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
package be.e_contract.mycarenet.ehealth.common;

import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Calendar;

import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Simple verifier for eHealth SAML assertions.
 *
 * @author Frank Cornelis
 */
public class AssertionVerifier {

	private final Element assertion;

	public AssertionVerifier(Element assertion) {
		this.assertion = assertion;
	}

	public X509Certificate verify() throws MarshalException, XMLSignatureException {
		if (null == this.assertion) {
			throw new IllegalArgumentException("missing assertion");
		}
		NodeList signatureNodeList = this.assertion.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (signatureNodeList.getLength() == 0) {
			throw new IllegalArgumentException("Cannot find Signature element");
		}
		Node signatureNode = signatureNodeList.item(0);
		KeyInfoKeySelector keySelector = new KeyInfoKeySelector();
		DOMValidateContext domValidateContext = new DOMValidateContext(keySelector, signatureNode);
		domValidateContext.setIdAttributeNS(this.assertion, null, "AssertionID");
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
		XMLSignature xmlSignature = xmlSignatureFactory.unmarshalXMLSignature(domValidateContext);
		boolean validSignature = xmlSignature.validate(domValidateContext);
		if (false == validSignature) {
			throw new SecurityException("invalid ds:Signature");
		}
		return keySelector.getCertificate();
	}

	public LocalDateTime getNotAfter() {
		if (null == this.assertion) {
			return null;
		}
		NodeList conditionsNodeList = this.assertion.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion",
				"Conditions");
		if (conditionsNodeList.getLength() == 0) {
			return null;
		}
		Element conditionsElement = (Element) conditionsNodeList.item(0);
		String notOnOrAfterAttributeValue = conditionsElement.getAttribute("NotOnOrAfter");
		if (null == notOnOrAfterAttributeValue) {
			return null;
		}
		if (notOnOrAfterAttributeValue.isEmpty()) {
			return null;
		}
		Calendar calendar = DatatypeConverter.parseDateTime(notOnOrAfterAttributeValue);
		return LocalDateTime.ofInstant(calendar.toInstant(), ZoneId.systemDefault());
	}
}
