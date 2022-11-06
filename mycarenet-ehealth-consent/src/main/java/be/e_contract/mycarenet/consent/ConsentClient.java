/*
 * Java MyCareNet Project.
 * Copyright (C) 2017-2022 e-Contract.be BV.
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

package be.e_contract.mycarenet.consent;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.mycarenet.consent.jaxb.hubservices.core.GetPatientConsentRequestType;
import be.e_contract.mycarenet.consent.jaxb.hubservices.core.GetPatientConsentResponseType;
import be.e_contract.mycarenet.consent.jaxws.ConsentPortType;
import be.e_contract.mycarenet.consent.jaxws.ConsentService;
import be.e_contract.mycarenet.ehealth.common.CredentialClient;
import be.e_contract.mycarenet.ehealth.common.WSSecuritySOAPHandler;

public class ConsentClient implements CredentialClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(ConsentClient.class);

	private final Dispatch<Source> dispatch;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	private final ConsentPortType port;

	public ConsentClient(String location) {
		ConsentService service = ConsentServiceFactory.newInstance();

		this.port = service.getConsentPort();

		QName portQName = new QName("urn:be:fgov:ehealth:consent:protocol:v1", "ConsentPort");
		this.dispatch = service.createDispatch(portQName, Source.class, Service.Mode.PAYLOAD);

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
		handlerChain.add(this.wsSecuritySOAPHandler);
		binding.setHandlerChain(handlerChain);
	}

	/**
	 * Sets the credentials to be used.
	 * 
	 * @param hokPrivateKey the eHealth holder-of-key authentication private key.
	 * @param samlAssertion the eHealth SAML assertion as string.
	 */
	@Override
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
		LOGGER.debug("response Source type: {}", responseSource.getClass().getName());
		return toString(responseSource);
	}

	public GetPatientConsentResponseType tarificationConsultation(GetPatientConsentRequestType request) {
		GetPatientConsentResponseType response = this.port.getPatientConsent(request);
		return response;
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
