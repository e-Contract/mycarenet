/*
 * Java MyCareNet Project.
 * Copyright (C) 2012-2023 e-Contract.be BV.
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

package be.e_contract.mycarenet.async;

import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.xml.crypto.dsig.Reference;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
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
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.common.WSSecurityCrypto;

/**
 * MyCareNet Asynchronous web service WS-Security implementation. The
 * implementation is based on WSS4J.
 * 
 * @author Frank Cornelis
 * 
 */
public class SecuritySOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Logger LOGGER = LoggerFactory.getLogger(SecuritySOAPHandler.class);

	private final SessionKey sessionKey;

	private final PackageLicenseKey packageLicenseKey;

	/**
	 * Main constructor.
	 * 
	 * @param sessionKey        the registered MyCareNet session key.
	 * @param packageLicenseKey the MyCareNet package license key.
	 */
	public SecuritySOAPHandler(SessionKey sessionKey, PackageLicenseKey packageLicenseKey) {
		this.sessionKey = sessionKey;
		this.packageLicenseKey = packageLicenseKey;
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
			LOGGER.error("outbound exception:" + e.getMessage(), e);
			throw new ProtocolException(e);
		}
		return true;
	}

	private void handleOutboundMessage(SOAPMessageContext context) throws SOAPException, WSSecurityException {
		LOGGER.debug("adding WS-Security header");
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		WSSecHeader wsSecHeader = new WSSecHeader(soapPart);
		wsSecHeader.insertSecurityHeader();

		WSSecUsernameToken usernameToken = new WSSecUsernameToken(wsSecHeader);
		usernameToken.setUserInfo(this.packageLicenseKey.getUsername(), this.packageLicenseKey.getPassword());
		usernameToken.setPasswordType(WSConstants.PASSWORD_TEXT);
		usernameToken.build();

		WSSecTimestamp wsSecTimeStamp = new WSSecTimestamp(wsSecHeader);
		wsSecTimeStamp.build();

		WSSecurityCrypto crypto = new WSSecurityCrypto(this.sessionKey);
		// WSSConfig wssConfig = new WSSConfig();
		// wssConfig.setWsiBSPCompliant(false);
		WSSecSignature sign = new WSSecSignature(wsSecHeader);
		sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
		sign.prepare(crypto);
		sign.appendBSTElementToHeader();
		Vector<WSEncryptionPart> signParts = new Vector<>();
		signParts.add(new WSEncryptionPart(wsSecTimeStamp.getId()));
		signParts.add(new WSEncryptionPart(usernameToken.getId()));
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(soapPart.getDocumentElement());
		signParts.add(new WSEncryptionPart(soapConstants.getBodyQName().getLocalPart(), soapConstants.getEnvelopeURI(),
				"Content"));
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
