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

package be.e_contract.mycarenet.etk;

import java.util.List;

import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.common.PayloadLogicalHandler;
import be.e_contract.mycarenet.ehealth.common.TracingClient;
import be.e_contract.mycarenet.ehealth.common.TracingSOAPHandler;
import be.e_contract.mycarenet.etk.jaxb.GetEtkRequest;
import be.e_contract.mycarenet.etk.jaxb.GetEtkResponse;
import be.e_contract.mycarenet.etk.jaxb.ObjectFactory;
import be.e_contract.mycarenet.etk.jaxb.SearchCriteriaType;
import be.e_contract.mycarenet.etk.jaxws.EtkDepotPortType;
import be.e_contract.mycarenet.etk.jaxws.EtkDepotService;

/**
 * Client for the eHealth Encryption Token Key web service.
 * 
 * @author Frank Cornelis
 * 
 */
public class EtkDepotClient implements TracingClient {

	private final EtkDepotPortType etkDepotPort;

	private final ObjectFactory objectFactory;

	private final PayloadLogicalHandler payloadLogicalHandler;

	private final TracingSOAPHandler tracingSOAPHandler;

	/**
	 * Main constructor.
	 * 
	 * @param location the URL of the eHealth Encryption Token Key web service.
	 */
	public EtkDepotClient(String location) {
		EtkDepotService service = EtkDepotServiceFactory.newInstance();
		this.etkDepotPort = service.getEtkDepotPort();

		this.payloadLogicalHandler = new PayloadLogicalHandler();
		this.tracingSOAPHandler = new TracingSOAPHandler();

		configureBindingProvider((BindingProvider) this.etkDepotPort, location);

		this.objectFactory = new ObjectFactory();
	}

	@Override
	public void setTracing(String userAgent, String from) {
		this.tracingSOAPHandler.setTracing(userAgent, from);
	}

	@SuppressWarnings("unchecked")
	private void configureBindingProvider(BindingProvider bindingProvider, String location) {
		bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		@SuppressWarnings("rawtypes")
		List handlerChain = binding.getHandlerChain();
		handlerChain.add(new LoggingHandler());
		handlerChain.add(this.payloadLogicalHandler);
		handlerChain.add(this.tracingSOAPHandler);
		binding.setHandlerChain(handlerChain);
	}

	/**
	 * Gives back the eHealth Encryption Token Key for the given identifier.
	 * 
	 * @param identifierType  the ETK identifier type.
	 * @param identifierValue
	 * @return
	 * @see be.e_contract.mycarenet.ehealth.common.IdentifierMapper
	 */
	public byte[] getEtk(String identifierType, String identifierValue) {
		return getEtk(identifierType, identifierValue, "");
	}

	/**
	 * Gives back the eHealth Encryption Token Key for the given identifier.
	 * 
	 * @param identifierType
	 * @param identifierValue
	 * @param applicationId
	 * @return
	 */
	public byte[] getEtk(String identifierType, String identifierValue, String applicationId) {
		GetEtkRequest getEtkRequest = this.objectFactory.createGetEtkRequest();
		SearchCriteriaType searchCriteria = this.objectFactory.createSearchCriteriaType();
		getEtkRequest.setSearchCriteria(searchCriteria);
		be.e_contract.mycarenet.etk.jaxb.IdentifierType identifier = this.objectFactory.createIdentifierType();
		searchCriteria.getIdentifier().add(identifier);
		identifier.setType(identifierType);
		identifier.setValue(identifierValue);
		identifier.setApplicationID(applicationId);

		GetEtkResponse getEtkResponse = this.etkDepotPort.getEtk(getEtkRequest);
		byte[] etk = getEtkResponse.getETK();
		return etk;
	}

	/**
	 * Gives back the inbound SOAP payload as string.
	 * 
	 * @return
	 */
	public String getPayload() {
		return this.payloadLogicalHandler.getPayload();
	}
}
