/*
 * Java MyCareNet Project.
 * Copyright (C) 2013-2022 e-Contract.be BV.
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

package be.e_contract.mycarenet.eh2ebox;

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
import javax.xml.ws.soap.MTOMFeature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.common.PayloadLogicalHandler;
import be.e_contract.mycarenet.eh2ebox.jaxb.publication.protocol.PublicationMessageType;
import be.e_contract.mycarenet.eh2ebox.jaxb.publication.protocol.SendMessageResponse;
import be.e_contract.mycarenet.eh2ebox.jaxws.publication.BusinessError;
import be.e_contract.mycarenet.eh2ebox.jaxws.publication.EhBoxPublicationPortType;
import be.e_contract.mycarenet.eh2ebox.jaxws.publication.EhBoxPublicationService;
import be.e_contract.mycarenet.eh2ebox.jaxws.publication.SystemError;
import be.e_contract.mycarenet.ehealth.common.CredentialClient;
import be.e_contract.mycarenet.ehealth.common.WSSecuritySOAPHandler;

/**
 * The eHealth eBox 2 Publication web service client. This client implements the
 * eHealth eBox 2 Publication web service version 3.0.
 * 
 * @author Frank Cornelis
 * 
 */
public class EHealth2eBoxPublicationClient implements CredentialClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(EHealth2eBoxPublicationClient.class);

	private final EhBoxPublicationPortType ehBoxPublicationPort;

	private final Dispatch<Source> publicationDispatch;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	private final PayloadLogicalHandler payloadLogicalHandler;

	/**
	 * Sets the authentication credentials.
	 * 
	 * @param hokPrivateKey the eHealth authentication private key.
	 * @param samlAssertion the eHealth STS SAML assertion as string.
	 */
	@Override
	public void setCredentials(PrivateKey hokPrivateKey, String samlAssertion) {
		this.wsSecuritySOAPHandler.setPrivateKey(hokPrivateKey);
		this.wsSecuritySOAPHandler.setAssertion(samlAssertion);
	}

	/**
	 * Main constructor.
	 * 
	 * @param location the URL of the eHealth Publication version 3.0 web service.
	 */
	public EHealth2eBoxPublicationClient(String location) {
		EhBoxPublicationService publicationService = EhBoxPublicationServiceFactory.newInstance();
		/*
		 * Nasty way to disable MTOM for Apache CXF.
		 */
		this.ehBoxPublicationPort = publicationService
				.getEhBoxPublicationPort(new MTOMFeature(false, 1024 * 1024 * 1024));

		QName publicationPortQName = new QName("urn:be:fgov:ehealth:ehbox:publication:protocol:v3",
				"ehBoxPublicationPort");
		this.publicationDispatch = publicationService.createDispatch(publicationPortQName, Source.class,
				Service.Mode.PAYLOAD);

		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		this.payloadLogicalHandler = new PayloadLogicalHandler();
		configureBindingProvider((BindingProvider) this.ehBoxPublicationPort, location);
		configureBindingProvider(this.publicationDispatch, location);
	}

	/**
	 * @param publicationMessage
	 * @return
	 * @throws BusinessError
	 * @throws SystemError
	 */
	public SendMessageResponse publish(PublicationMessageType publicationMessage) throws BusinessError, SystemError {

		SendMessageResponse sendMessageResponse = this.ehBoxPublicationPort.sendMessage(publicationMessage);
		return sendMessageResponse;
	}

	@SuppressWarnings("unchecked")
	private void configureBindingProvider(BindingProvider bindingProvider, String location) {
		bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		@SuppressWarnings("rawtypes")
		List handlerChain = binding.getHandlerChain();
		handlerChain.add(this.wsSecuritySOAPHandler);
		handlerChain.add(new LoggingHandler());
		handlerChain.add(this.payloadLogicalHandler);
		binding.setHandlerChain(handlerChain);
	}

	public Element invoke(Element request) {
		Source responseSource = this.publicationDispatch.invoke(new DOMSource(request));
		Element responseElement = toElement(responseSource);
		return responseElement;
	}

	public String invoke(String request) {
		Source responseSource = this.publicationDispatch.invoke(new StreamSource(new StringReader(request)));
		LOGGER.debug("response Source type: {}", responseSource.getClass().getName());
		return toString(responseSource);
	}

	/**
	 * Returns the SOAP payload as a string.
	 * 
	 * @return
	 */
	public String getPayload() {
		return this.payloadLogicalHandler.getPayload();
	}

	private String toString(Source source) {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
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
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
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
