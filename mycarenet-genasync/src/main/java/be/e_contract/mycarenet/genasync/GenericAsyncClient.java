/*
 * Java MyCareNet Project.
 * Copyright (C) 2018 e-Contract.be BVBA.
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

package be.e_contract.mycarenet.genasync;

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
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;
import javax.xml.ws.soap.AddressingFeature;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.ehealth.common.WSAddressingSOAPHandler;
import be.e_contract.mycarenet.ehealth.common.WSSecuritySOAPHandler;
import be.e_contract.mycarenet.genasync.jaxws.GenericAsync;
import be.e_contract.mycarenet.genasync.jaxws.GenericAsyncService;

public class GenericAsyncClient {

	private static final Log LOG = LogFactory.getLog(GenericAsyncClient.class);

	private final Dispatch<Source> dispatch;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	private final GenericAsync port;

	public GenericAsyncClient(String location) {
		GenericAsyncService service = GenericAsyncServiceFactory.newInstance();

		this.port = service.getGenericAsyncSOAP(new AddressingFeature(true));

		QName portQName = new QName("urn:be:cin:nip:async:generic", "GenericAsyncSOAP");
		this.dispatch = service.createDispatch(portQName, Source.class, Service.Mode.PAYLOAD,
				new AddressingFeature(true));

		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();

		configureBindingProvider(this.dispatch, location);
		configureBindingProvider((BindingProvider) this.port, location);
	}

	@SuppressWarnings("unchecked")
	private void configureBindingProvider(BindingProvider bindingProvider, String location) {
		bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		@SuppressWarnings("rawtypes")
		List handlerChain = binding.getHandlerChain();
		handlerChain.add(new WSAddressingSOAPHandler("urn:nip:destination:io:MULTICAST"));
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

	/**
	 * Invokes a method on the eHealthBox consultation web service using the
	 * low-level SOAP payload.
	 * 
	 * @param request
	 * @return
	 */
	public String invoke(String request) {
		Source responseSource = this.dispatch.invoke(new StreamSource(new StringReader(request)));
		LOG.debug("response Source type: " + responseSource.getClass().getName());
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
}
