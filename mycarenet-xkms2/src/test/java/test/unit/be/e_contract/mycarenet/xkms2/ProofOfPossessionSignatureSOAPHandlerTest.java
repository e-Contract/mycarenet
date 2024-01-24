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

package test.unit.be.e_contract.mycarenet.xkms2;

import java.io.StringWriter;
import java.util.Calendar;
import java.util.Date;

import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPBodyElement;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.easymock.EasyMock;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.xkms2.ProofOfPossessionSignatureSOAPHandler;
import be.e_contract.mycarenet.xkms2.XKMS2ServiceFactory;

public class ProofOfPossessionSignatureSOAPHandlerTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProofOfPossessionSignatureSOAPHandlerTest.class);

	@Test
	public void testHandleMessage() throws Exception {
		LOGGER.debug("testing");
		SessionKey sessionKey = new SessionKey();
		Date notBefore = new Date();
		Calendar notAfterCalendar = Calendar.getInstance();
		notAfterCalendar.setTime(notBefore);
		notAfterCalendar.add(Calendar.HOUR_OF_DAY, 1);
		Date notAfter = notAfterCalendar.getTime();
		sessionKey.setValidity(notBefore, notAfter);
		ProofOfPossessionSignatureSOAPHandler testedInstance = new ProofOfPossessionSignatureSOAPHandler();
		testedInstance.setSessionKey(sessionKey);
		testedInstance.setPrototypeKeyBindingId("prototype-key-binding-id");

		SOAPMessageContext mockSoapMessageContext = EasyMock.createMock(SOAPMessageContext.class);
		EasyMock.expect(mockSoapMessageContext.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY)).andReturn(true);

		MessageFactory messageFactory = MessageFactory.newInstance();
		SOAPMessage soapMessage = messageFactory.createMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();
		SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
		SOAPBody soapBody = soapEnvelope.getBody();
		SOAPBodyElement soapBodyElement = soapBody
				.addBodyElement(new QName(XKMS2ServiceFactory.XKMS2_NAMESPACE, "RegisterRequest"));
		soapBodyElement.addChildElement(new QName(XKMS2ServiceFactory.XKMS2_NAMESPACE, "ProofOfPossession"));
		SOAPElement prototypeElement = soapBodyElement
				.addChildElement(new QName(XKMS2ServiceFactory.XKMS2_NAMESPACE, "PrototypeKeyBinding"));
		prototypeElement.setAttribute("Id", "prototype-key-binding-id");

		EasyMock.expect(mockSoapMessageContext.getMessage()).andReturn(soapMessage);

		// prepare
		EasyMock.replay(mockSoapMessageContext);

		// operate
		testedInstance.handleMessage(mockSoapMessageContext);

		// verify
		EasyMock.verify(mockSoapMessageContext);
		LOGGER.debug(toString(soapPart));
	}

	private String toString(Node node) throws Exception {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		transformerFactory.setAttribute("indent-number", 4);
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		StringWriter stringWriter = new StringWriter();
		transformer.transform(new DOMSource(node), new StreamResult(stringWriter));
		return stringWriter.toString();
	}
}
