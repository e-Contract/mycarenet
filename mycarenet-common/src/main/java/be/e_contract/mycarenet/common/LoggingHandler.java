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

package be.e_contract.mycarenet.common;

import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.Set;

import javax.activation.DataHandler;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * JAX-WS SOAP handler to provides logging of the SOAP messages using the
 * Commons Logging framework.
 * 
 * @author Frank Cornelis
 * 
 */
public class LoggingHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Log LOG = LogFactory.getLog(LoggingHandler.class);

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		if (false == LOG.isDebugEnabled()) {
			return true;
		}
		logMessage(context);
		return true;
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		if (false == LOG.isDebugEnabled()) {
			return true;
		}
		logMessage(context);
		return true;
	}

	private void logMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		LOG.debug("outbound message: " + outboundProperty);
		SOAPMessage soapMessage = context.getMessage();
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try {
			soapMessage.writeTo(outputStream);
		} catch (Exception e) {
			LOG.error("SOAP error: " + e.getMessage());
		}
		String message = outputStream.toString();
		LOG.debug("SOAP message: " + message);
		if (false == outboundProperty) {
			@SuppressWarnings("unchecked")
			Map<String, DataHandler> inboundMessageAttachments = (Map<String, DataHandler>) context
					.get(MessageContext.INBOUND_MESSAGE_ATTACHMENTS);
			Set<String> attachmentContentIds = inboundMessageAttachments
					.keySet();
			LOG.debug("attachment content ids: " + attachmentContentIds);
		}
	}

	@Override
	public void close(MessageContext context) {
	}

	@Override
	public Set<QName> getHeaders() {
		return null;
	}
}
