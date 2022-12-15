/*
 * Java MyCareNet Project.
 * Copyright (C) 2022 e-Contract.be BV.
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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracing SOAP handler.
 *
 * @author Frank Cornelis
 */
public class TracingSOAPHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Logger LOGGER = LoggerFactory.getLogger(TracingSOAPHandler.class);

	private String userAgent;

	private String from;

	public void setTracing(String userAgent, String from) {
		this.userAgent = userAgent;
		this.from = from;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (false == outboundProperty) {
			return true;
		}
		if (null == this.userAgent) {
			return true;
		}
		Map<String, List<String>> headers = (Map<String, List<String>>) context
				.get(MessageContext.HTTP_REQUEST_HEADERS);
		if (null == headers) {
			headers = new HashMap<>();
			context.put(MessageContext.HTTP_REQUEST_HEADERS, headers);
		}
		headers.put("User-Agent", Collections.singletonList(this.userAgent));
		headers.put("From", Collections.singletonList(this.from));
		LOGGER.debug("setting tracing headers: {} - {}", this.userAgent, this.from);
		return true;
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
