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

package be.e_contract.mycarenet.common;

import java.io.StringWriter;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.LogicalMessage;
import javax.xml.ws.handler.LogicalHandler;
import javax.xml.ws.handler.LogicalMessageContext;
import javax.xml.ws.handler.MessageContext;

/**
 * JAX-WS SOAP handler implementation that captures the inbound SOAP payload.
 * 
 * @author Frank Cornelis
 * 
 */
public class PayloadLogicalHandler implements
		LogicalHandler<LogicalMessageContext> {

	private String payload;

	@Override
	public boolean handleMessage(LogicalMessageContext context) {
		storePayload(context);
		return true;
	}

	@Override
	public boolean handleFault(LogicalMessageContext context) {
		storePayload(context);
		return true;
	}

	/**
	 * Gives back the inbound SOAP payload as string.
	 * 
	 * @return
	 */
	public String getPayload() {
		return this.payload;
	}

	private void storePayload(LogicalMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (outboundProperty) {
			return;
		}
		LogicalMessage logicalMessage = context.getMessage();
		Source payloadSource = logicalMessage.getPayload();
		this.payload = toString(payloadSource);
	}

	private String toString(Source source) {
		TransformerFactory factory = TransformerFactory.newInstance();
		Transformer transformer;
		try {
			transformer = factory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		}
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		try {
			transformer.transform(source, result);
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
		return stringWriter.toString();
	}

	@Override
	public void close(MessageContext context) {
	}
}
