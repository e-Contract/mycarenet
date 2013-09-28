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

import java.security.PrivateKey;
import java.util.List;

import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.GetBoxInfoRequestType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.GetBoxInfoResponseType;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.BusinessError;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.EhBoxConsultationPortType;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.EhBoxConsultationService;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.SystemError;

public class EHealthBoxClient {

	private final EhBoxConsultationPortType ehBoxConsultationPort;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	public EHealthBoxClient(String location) throws Exception {
		EhBoxConsultationService service = EhBoxConsultationServiceFactory
				.newInstance();
		this.ehBoxConsultationPort = service.getEhBoxConsultationPort();

		BindingProvider bindingProvider = (BindingProvider) this.ehBoxConsultationPort;
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List handlerChain = binding.getHandlerChain();
		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		handlerChain.add(this.wsSecuritySOAPHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);
	}

	public GetBoxInfoResponseType getBoxInfo(PrivateKey hokPrivateKey,
			String samlAssertion) throws BusinessError, SystemError {
		GetBoxInfoRequestType getBoxInfoRequest = new GetBoxInfoRequestType();
		this.wsSecuritySOAPHandler.setPrivateKey(hokPrivateKey);
		this.wsSecuritySOAPHandler.setAssertion(samlAssertion);
		GetBoxInfoResponseType getBoxInfoResponse = this.ehBoxConsultationPort
				.getBoxInfo(getBoxInfoRequest);
		return getBoxInfoResponse;
	}
}
