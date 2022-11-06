/*
 * Java MyCareNet Project.
 * Copyright (C) 2018-2022 e-Contract.be BV.
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

import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * WS-Addressing JAX-WS SOAP handler implementation for eHealth web services
 * that require custom values.
 * 
 * @author Frank Cornelis
 *
 */
public class WSAddressingSOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Logger LOGGER = LoggerFactory.getLogger(WSAddressingSOAPHandler.class);

	private final String to;

	public WSAddressingSOAPHandler(String to) {
		this.to = to;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		if (null == this.to) {
			return true;
		}
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

	private void handleOutboundMessage(SOAPMessageContext context) throws SOAPException {
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();
		SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
		SOAPHeader header = soapEnvelope.getHeader();
		NodeList toNodeList = header.getElementsByTagNameNS("http://www.w3.org/2005/08/addressing", "To");
		if (toNodeList.getLength() != 0) {
			Element toElement = (Element) toNodeList.item(0);
			toElement.setTextContent(this.to);
		}
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
