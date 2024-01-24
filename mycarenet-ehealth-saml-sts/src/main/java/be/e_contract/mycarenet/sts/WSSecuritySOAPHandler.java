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

package be.e_contract.mycarenet.sts;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.xml.crypto.dsig.Reference;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.SOAPConstants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.mycarenet.common.WSSecurityCrypto;

/**
 * WS-Security JAX-WS SOAP handler for the eHealth STS web service. The
 * implementation used WSS4J to create the WS-Security header.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSSecuritySOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Logger LOGGER = LoggerFactory.getLogger(WSSecuritySOAPHandler.class);

	private PrivateKey privateKey;

	private X509Certificate certificate;

	/**
	 * Sets the eID authentication private key used to sign according to
	 * WS-Security.
	 * 
	 * @param privateKey
	 */
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * Sets the eID authentication certificate used to sign according to
	 * WS-Security.
	 * 
	 * @param certificate
	 */
	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
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

	private void handleOutboundMessage(SOAPMessageContext context) throws WSSecurityException {
		LOGGER.debug("adding WS-Security header");
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		WSSecHeader wsSecHeader = new WSSecHeader(soapPart);
		wsSecHeader.insertSecurityHeader();

		WSSecTimestamp wsSecTimeStamp = new WSSecTimestamp(wsSecHeader);
		wsSecTimeStamp.setTimeToLive(60);
		wsSecTimeStamp.build();

		WSSecurityCrypto crypto = new WSSecurityCrypto(this.privateKey, this.certificate);
		// WSSConfig wssConfig = WSSConfig.getNewInstance();
		// wssConfig.setWsiBSPCompliant(false);
		WSSecSignature sign = new WSSecSignature(wsSecHeader);
		sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
		sign.prepare(crypto);
		String bstId = sign.getBSTTokenId();
		sign.appendBSTElementToHeader();
		Vector<WSEncryptionPart> signParts = new Vector<>();
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(soapPart.getDocumentElement());
		signParts.add(new WSEncryptionPart(soapConstants.getBodyQName().getLocalPart(), soapConstants.getEnvelopeURI(),
				"Content"));
		signParts.add(new WSEncryptionPart(bstId));
		signParts.add(new WSEncryptionPart(wsSecTimeStamp.getId()));
		List<Reference> referenceList = sign.addReferencesToSign(signParts);
		sign.computeSignature(referenceList, false, null);
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
