/*
 * Java MyCareNet Project.
 * Copyright (C) 2014-2015 e-Contract.be BVBA.
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

package be.e_contract.mycarenet.genins;

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
import be.e_contract.mycarenet.ehealth.common.WSSecuritySOAPHandler;
import be.e_contract.mycarenet.genins.jaxb.protocol.GetInsurabilityAsXmlOrFlatRequestType;
import be.e_contract.mycarenet.genins.jaxb.protocol.GetInsurabilityResponseType;
import be.e_contract.mycarenet.genins.jaxws.GenericInsurabilityPortType;
import be.e_contract.mycarenet.genins.jaxws.GenericInsurabilityService;
import be.e_contract.mycarenet.genins.jaxws.SystemError;

public class GenericInsurabilityClient {

	private final GenericInsurabilityPortType port;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	private final Dispatch<Source> dispatch;

	public GenericInsurabilityClient(String location) {
		GenericInsurabilityService service = GenericInsurabilityServiceFactory
				.newInstance();
		this.port = service.getGenericInsurabilityServiceSOAP11();

		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		configureBindingProvider((BindingProvider) this.port, location);

		QName portQName = new QName(
				"urn:be:fgov:ehealth:genericinsurability:protocol:v1",
				"GenericInsurabilityServiceSOAP11");
		this.dispatch = service.createDispatch(portQName, Source.class,
				Service.Mode.PAYLOAD);
		configureBindingProvider(this.dispatch, location);
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

	public GetInsurabilityResponseType getInsurability(
			GetInsurabilityAsXmlOrFlatRequestType body) throws SystemError {
		return this.port.getInsurability(body);
	}

	/**
	 * Invokes a method on the eHealthBox consultation web service using the
	 * low-level SOAP payload.
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
	 * Invokes a method on the eHealthBox consultation web service using the
	 * low-level SOAP payload.
	 * 
	 * @param request
	 * @return
	 */
	public String invoke(String request) {
		Source responseSource = this.dispatch.invoke(new StreamSource(
				new StringReader(request)));
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
