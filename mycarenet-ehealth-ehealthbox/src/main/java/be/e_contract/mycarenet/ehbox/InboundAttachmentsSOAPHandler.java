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

package be.e_contract.mycarenet.ehbox;

import java.util.Map;
import java.util.Set;

import javax.activation.DataHandler;
import javax.xml.namespace.QName;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

/**
 * A JAX-WS SOAP handler that catches the inbound SOAP attachments.
 * 
 * @author Frank Cornelis
 * 
 */
public class InboundAttachmentsSOAPHandler implements
		SOAPHandler<SOAPMessageContext> {

	private Map<String, DataHandler> inboundMessageAttachments;

	@SuppressWarnings("unchecked")
	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (false == outboundProperty) {
			this.inboundMessageAttachments = (Map<String, DataHandler>) context
					.get(MessageContext.INBOUND_MESSAGE_ATTACHMENTS);
		}
		return true;
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
	 * Gives back the captures inbound SOAP attachments.
	 * 
	 * @return
	 */
	public Map<String, DataHandler> getInboundMessageAttachments() {
		return this.inboundMessageAttachments;
	}
}
