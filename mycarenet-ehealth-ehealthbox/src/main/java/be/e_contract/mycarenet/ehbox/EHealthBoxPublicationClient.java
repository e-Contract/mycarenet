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
import be.e_contract.mycarenet.ehbox.jaxb.publication.protocol.PublicationMessageType;
import be.e_contract.mycarenet.ehbox.jaxb.publication.protocol.SendMessageResponse;
import be.e_contract.mycarenet.ehbox.jaxws.publication.BusinessError;
import be.e_contract.mycarenet.ehbox.jaxws.publication.EhBoxPublicationPortType;
import be.e_contract.mycarenet.ehbox.jaxws.publication.EhBoxPublicationService;
import be.e_contract.mycarenet.ehbox.jaxws.publication.SystemError;
import be.e_contract.mycarenet.ehealth.common.WSSecuritySOAPHandler;

/**
 * The eHealthBox Publication web service client. This client implementation the
 * eHealthBox Publication web service version 3.0.
 * 
 * @author Frank Cornelis
 * 
 */
public class EHealthBoxPublicationClient {

	private static final Log LOG = LogFactory
			.getLog(EHealthBoxPublicationClient.class);

	private final EhBoxPublicationPortType ehBoxPublicationPort;

	private final Dispatch<Source> publicationDispatch;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	public void setCredentials(PrivateKey hokPrivateKey, String samlAssertion) {
		this.wsSecuritySOAPHandler.setPrivateKey(hokPrivateKey);
		this.wsSecuritySOAPHandler.setAssertion(samlAssertion);
	}

	public EHealthBoxPublicationClient(String location) {
		EhBoxPublicationService publicationService = EhBoxPublicationServiceFactory
				.newInstance();
		this.ehBoxPublicationPort = publicationService
				.getEhBoxPublicationPort();

		QName publicationPortQName = new QName(
				"urn:be:fgov:ehealth:ehbox:publication:protocol:v3",
				"ehBoxPublicationPort");
		this.publicationDispatch = publicationService.createDispatch(
				publicationPortQName, Source.class, Service.Mode.PAYLOAD);

		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		configureBindingProvider((BindingProvider) this.ehBoxPublicationPort,
				location);
		configureBindingProvider(this.publicationDispatch, location);
	}

	public SendMessageResponse publish(
			PublicationMessageType publicationMessage,
			PrivateKey hokPrivateKey, String samlAssertion)
			throws BusinessError, SystemError {

		SendMessageResponse sendMessageResponse = this.ehBoxPublicationPort
				.sendMessage(publicationMessage);
		return sendMessageResponse;
	}

	private void configureBindingProvider(BindingProvider bindingProvider,
			String location) {
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List handlerChain = binding.getHandlerChain();
		handlerChain.add(this.wsSecuritySOAPHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);
	}

	public Element invoke(Element request) {
		Source responseSource = this.publicationDispatch.invoke(new DOMSource(
				request));
		Element responseElement = toElement(responseSource);
		return responseElement;
	}

	public String invoke(String request) {
		Source responseSource = this.publicationDispatch
				.invoke(new StreamSource(new StringReader(request)));
		LOG.debug("response Source type: "
				+ responseSource.getClass().getName());
		return toString(responseSource);
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
