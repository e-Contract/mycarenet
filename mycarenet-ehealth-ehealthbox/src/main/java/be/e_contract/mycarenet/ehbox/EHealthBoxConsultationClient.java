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

import java.io.StringReader;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;

import javax.activation.DataHandler;
import javax.xml.namespace.QName;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.DeleteMessageRequestType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.DeleteMessageResponseType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.GetBoxInfoRequestType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.GetBoxInfoResponseType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.GetFullMessageResponseType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.GetMessageListResponseType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.GetMessagesListRequestType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.MessageRequestType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.MoveMessageRequestType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.MoveMessageResponseType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.ObjectFactory;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.BusinessError;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.EhBoxConsultationPortType;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.EhBoxConsultationService;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.SystemError;
import be.e_contract.mycarenet.ehealth.common.WSSecuritySOAPHandler;

/**
 * The eHealthBox Consultation web service client. This client implementation
 * the eHealthBox Consultation web service version 3.0.
 * 
 * @author Frank Cornelis
 * 
 */
public class EHealthBoxConsultationClient {

	private static final Log LOG = LogFactory
			.getLog(EHealthBoxConsultationClient.class);

	private final EhBoxConsultationPortType ehBoxConsultationPort;

	private final Dispatch<Source> consultationDispatch;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	private final ObjectFactory objectFactory;

	private final InboundAttachmentsSOAPHandler inboundAttachmentsSOAPHandler;

	/**
	 * Sets the credentials to be used.
	 * 
	 * @param hokPrivateKey
	 *            the eHealth holder-of-key authentication private key.
	 * @param samlAssertion
	 *            the eHealth SAML assertion as string.
	 */
	public void setCredentials(PrivateKey hokPrivateKey, String samlAssertion) {
		this.wsSecuritySOAPHandler.setPrivateKey(hokPrivateKey);
		this.wsSecuritySOAPHandler.setAssertion(samlAssertion);
	}

	/**
	 * Main constructor.
	 * 
	 * @param location
	 *            the URL of the eHealthBox Consultation version 3.0 web
	 *            service.
	 */
	public EHealthBoxConsultationClient(String location) {
		EhBoxConsultationService consultationService = EhBoxConsultationServiceFactory
				.newInstance();
		this.ehBoxConsultationPort = consultationService
				.getEhBoxConsultationPort();

		QName consultationPortQName = new QName(
				"urn:be:fgov:ehealth:ehbox:consultation:protocol:v3",
				"ehBoxConsultationPort");
		this.consultationDispatch = consultationService.createDispatch(
				consultationPortQName, Source.class, Service.Mode.PAYLOAD);

		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		this.inboundAttachmentsSOAPHandler = new InboundAttachmentsSOAPHandler();
		configureBindingProvider((BindingProvider) this.ehBoxConsultationPort,
				location);
		configureBindingProvider(this.consultationDispatch, location);
		this.objectFactory = new ObjectFactory();
	}

	private void configureBindingProvider(BindingProvider bindingProvider,
			String location) {
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List handlerChain = binding.getHandlerChain();
		handlerChain.add(this.wsSecuritySOAPHandler);
		handlerChain.add(this.inboundAttachmentsSOAPHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);
	}

	/**
	 * Gives back the eHealthBox information.
	 * 
	 * 
	 * @return
	 * @throws BusinessError
	 * @throws SystemError
	 */
	public GetBoxInfoResponseType getBoxInfo() throws BusinessError,
			SystemError {
		GetBoxInfoRequestType getBoxInfoRequest = this.objectFactory
				.createGetBoxInfoRequestType();
		GetBoxInfoResponseType getBoxInfoResponse = this.ehBoxConsultationPort
				.getBoxInfo(getBoxInfoRequest);
		return getBoxInfoResponse;
	}

	/**
	 * Gives back the message list from the "INBOX" source.
	 * 
	 * @return
	 * @throws BusinessError
	 * @throws SystemError
	 */
	public GetMessageListResponseType getMessagesList() throws BusinessError,
			SystemError {
		return getMessagesList("INBOX");
	}

	/**
	 * Gives back the messages list for the given source. Source can be for
	 * example "INBOX".
	 * 
	 * @param source
	 * @return
	 * @throws BusinessError
	 * @throws SystemError
	 */
	public GetMessageListResponseType getMessagesList(String source)
			throws BusinessError, SystemError {
		GetMessagesListRequestType getMessagesListRequest = this.objectFactory
				.createGetMessagesListRequestType();
		getMessagesListRequest.setSource(source);
		GetMessageListResponseType getMessageListResponse = this.ehBoxConsultationPort
				.getMessagesList(getMessagesListRequest);
		return getMessageListResponse;
	}

	/**
	 * Gives back a message from the INBOX.
	 * 
	 * @param messageId
	 * @return
	 * @throws BusinessError
	 * @throws SystemError
	 */
	public GetFullMessageResponseType getMessage(String messageId)
			throws BusinessError, SystemError {
		return getMessage("INBOX", messageId);
	}

	/**
	 * Gives back a message.
	 * 
	 * @param source
	 * @param messageId
	 * @return
	 * @throws BusinessError
	 * @throws SystemError
	 */
	public GetFullMessageResponseType getMessage(String source, String messageId)
			throws BusinessError, SystemError {
		MessageRequestType messageRequest = this.objectFactory
				.createMessageRequestType();
		messageRequest.setSource(source);
		messageRequest.setMessageId(messageId);
		GetFullMessageResponseType message = this.ehBoxConsultationPort
				.getFullMessage(messageRequest);
		return message;
	}

	/**
	 * Delete a message from the "INBOX" source.
	 * 
	 * @param messageId
	 * @return
	 * @throws BusinessError
	 * @throws SystemError
	 */
	public DeleteMessageResponseType deleteMessage(String messageId)
			throws BusinessError, SystemError {
		return deleteMessage("INBOX", messageId);
	}

	/**
	 * Delete a message.
	 * 
	 * @param source
	 * @param messageId
	 * @return
	 * @throws BusinessError
	 * @throws SystemError
	 */
	public DeleteMessageResponseType deleteMessage(String source,
			String messageId) throws BusinessError, SystemError {
		DeleteMessageRequestType deleteMessageRequest = this.objectFactory
				.createDeleteMessageRequestType();
		deleteMessageRequest.setSource(source);
		deleteMessageRequest.getMessageId().add(messageId);
		return this.ehBoxConsultationPort.deleteMessage(deleteMessageRequest);
	}

	/**
	 * Moves a message.
	 * 
	 * @param moveMessageRequest
	 * @return
	 * @throws BusinessError
	 * @throws SystemError
	 */
	public MoveMessageResponseType moveMessage(
			MoveMessageRequestType moveMessageRequest) throws BusinessError,
			SystemError {
		return this.ehBoxConsultationPort.moveMessage(moveMessageRequest);
	}

	/**
	 * Invokes a method on the eHealthBox consultation web service using the
	 * low-level SOAP payload.
	 * 
	 * @param request
	 * @return
	 */
	public Element invoke(Element request) {
		Source responseSource = this.consultationDispatch.invoke(new DOMSource(
				request));
		Element responseElement = toElement(responseSource);
		return responseElement;
	}

	/**
	 * Invokes a method on the eHealthBox consultation web service using the
	 * low-level SOAP payload.
	 * 
	 * @param request
	 * @return
	 */
	public String invoke(String request) {
		Source responseSource = this.consultationDispatch
				.invoke(new StreamSource(new StringReader(request)));
		LOG.debug("response Source type: "
				+ responseSource.getClass().getName());
		return toString(responseSource);
	}

	/**
	 * Gives back the inbound SOAP attachments.
	 * 
	 * @return a map of data handlers keyed on attachment identifiers.
	 */
	public Map<String, DataHandler> getMessageAttachments() {
		return this.inboundAttachmentsSOAPHandler
				.getInboundMessageAttachments();
	}

	private String toString(Source source) {
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		}
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		try {
			transformer.transform(source, result);
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
		return stringWriter.toString();
	}

	private Element toElement(Source source) {
		if (source instanceof DOMSource) {
			DOMSource domSource = (DOMSource) source;
			return (Element) domSource.getNode();
		}
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		}
		DOMResult domResult = new DOMResult();
		try {
			transformer.transform(source, domResult);
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
		Document document = (Document) domResult.getNode();
		return (Element) document.getDocumentElement();
	}
}
