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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.util.WSSecurityUtil;

import be.e_contract.mycarenet.common.WSSecurityCrypto;

public class WSSecuritySOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Log LOG = LogFactory
			.getLog(WSSecuritySOAPHandler.class);

	private PrivateKey privateKey;

	private X509Certificate certificate;

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
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
			throws WSSecurityException {
		LOG.debug("adding WS-Security header");
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		WSSecHeader wsSecHeader = new WSSecHeader();
		wsSecHeader.insertSecurityHeader(soapPart);

		WSSecTimestamp wsSecTimeStamp = new WSSecTimestamp();
		wsSecTimeStamp.setTimeToLive(60);
		wsSecTimeStamp.build(soapPart, wsSecHeader);

		WSSecurityCrypto crypto = new WSSecurityCrypto(this.privateKey,
				this.certificate);
		WSSConfig wssConfig = new WSSConfig();
		wssConfig.setWsiBSPCompliant(false);
		WSSecSignature sign = new WSSecSignature(wssConfig);
		sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
		sign.prepare(soapPart, crypto, wsSecHeader);
		String bstId = sign.getBSTTokenId();
		sign.appendBSTElementToHeader(wsSecHeader);
		Vector<WSEncryptionPart> signParts = new Vector<WSEncryptionPart>();
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(soapPart
				.getDocumentElement());
		signParts.add(new WSEncryptionPart(soapConstants.getBodyQName()
				.getLocalPart(), soapConstants.getEnvelopeURI(), "Content"));
		signParts.add(new WSEncryptionPart(bstId));
		signParts.add(new WSEncryptionPart(wsSecTimeStamp.getId()));
		List<Reference> referenceList = sign.addReferencesToSign(signParts,
				wsSecHeader);
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
