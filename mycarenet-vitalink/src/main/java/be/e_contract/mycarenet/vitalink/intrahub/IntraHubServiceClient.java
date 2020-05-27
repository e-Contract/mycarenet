/*
 * Java MyCareNet Project.
 * Copyright (C) 2018-2020 e-Contract.be BV.
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

package be.e_contract.mycarenet.vitalink.intrahub;

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

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.ehealth.common.CredentialClient;
import be.e_contract.mycarenet.ehealth.common.WSSecuritySOAPHandler;
import be.e_contract.mycarenet.vitalink.intrahub.jaxws.IntraHubPortType;
import be.e_contract.mycarenet.vitalink.intrahub.jaxws.IntraHubService;

public class IntraHubServiceClient implements CredentialClient {

	private final IntraHubPortType port;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	private final Dispatch<Source> dispatch;

	/**
	 * Main constructor.
	 * 
	 * @param location
	 *            location of the web service endpoint.
	 */
	public IntraHubServiceClient(String location) {
		IntraHubService service = IntraHubServiceFactory.newInstance();
		this.port = service.getIntraHubPort();

		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		configureBindingProvider((BindingProvider) this.port, location);

		QName portQName = new QName("http://www.ehealth.fgov.be/intrahub/protocol/v3", "IntraHubPort");
		this.dispatch = service.createDispatch(portQName, Source.class, Service.Mode.PAYLOAD);
		configureBindingProvider(this.dispatch, location);
	}

	private void configureBindingProvider(BindingProvider bindingProvider, String location) {
		bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List handlerChain = binding.getHandlerChain();
		handlerChain.add(this.wsSecuritySOAPHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);
	}

	/**
	 * Sets the credentials to be used.
	 * 
	 * @param hokPrivateKey
	 *            the eHealth holder-of-key authentication private key.
	 * @param samlAssertion
	 *            the eHealth SAML assertion as string.
	 */
	@Override
	public void setCredentials(PrivateKey hokPrivateKey, String samlAssertion) {
		this.wsSecuritySOAPHandler.setPrivateKey(hokPrivateKey);
		this.wsSecuritySOAPHandler.setAssertion(samlAssertion);
	}

	/**
	 * Invokes a method on the eHealth IntraHub web service using the low-level SOAP
	 * payload.
	 * 
	 * @param request
	 * @return
	 */
	public Element invoke(Element request) {
		Source responseSource = this.dispatch.invoke(new DOMSource(request));
		Element responseElement = toElement(responseSource);
		return responseElement;
	}

	/**
	 * Invokes a method on the eHealth IntraHub web service using the low-level SOAP
	 * payload.
	 * 
	 * @param request
	 * @return
	 */
	public String invoke(String request) {
		Source responseSource = this.dispatch.invoke(new StreamSource(new StringReader(request)));
		return toString(responseSource);
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
