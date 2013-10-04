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

package be.e_contract.mycarenet.etk;

import java.util.List;

import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.etk.jaxb.GetEtkRequest;
import be.e_contract.mycarenet.etk.jaxb.GetEtkResponse;
import be.e_contract.mycarenet.etk.jaxb.IdentifierType;
import be.e_contract.mycarenet.etk.jaxb.ObjectFactory;
import be.e_contract.mycarenet.etk.jaxb.SearchCriteriaType;
import be.e_contract.mycarenet.etk.jaxws.EtkDepotPortType;
import be.e_contract.mycarenet.etk.jaxws.EtkDepotService;

public class EtkDepotClient {

	private final EtkDepotPortType etkDepotPort;

	private final ObjectFactory objectFactory;

	public EtkDepotClient(String location) {
		EtkDepotService service = EtkDepotServiceFactory.newInstance();
		this.etkDepotPort = service.getEtkDepotPort();

		configureBindingProvider((BindingProvider) this.etkDepotPort, location);

		this.objectFactory = new ObjectFactory();
	}

	private void configureBindingProvider(BindingProvider bindingProvider,
			String location) {
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List handlerChain = binding.getHandlerChain();
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);
	}

	public byte[] getEtk(String inss) {
		GetEtkRequest getEtkRequest = this.objectFactory.createGetEtkRequest();
		SearchCriteriaType searchCriteria = this.objectFactory
				.createSearchCriteriaType();
		getEtkRequest.setSearchCriteria(searchCriteria);
		IdentifierType identifier = this.objectFactory.createIdentifierType();
		searchCriteria.getIdentifier().add(identifier);
		identifier.setType("SSIN");
		identifier.setValue(inss);
		identifier.setApplicationID("");

		GetEtkResponse getEtkResponse = this.etkDepotPort.getEtk(getEtkRequest);
		byte[] etk = getEtkResponse.getETK();
		return etk;
	}
}
