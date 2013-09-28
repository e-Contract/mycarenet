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

import javax.xml.namespace.QName;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;

import org.w3c.dom.Element;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.GetBoxInfoRequestType;
import be.e_contract.mycarenet.ehbox.jaxb.consultation.protocol.GetBoxInfoResponseType;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.BusinessError;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.EhBoxConsultationPortType;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.EhBoxConsultationService;
import be.e_contract.mycarenet.ehbox.jaxws.consultation.SystemError;

public class EHealthBoxClient {

	private final EhBoxConsultationPortType ehBoxConsultationPort;

	private final Dispatch<Source> dispatch;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	public EHealthBoxClient(String location) throws Exception {
		EhBoxConsultationService service = EhBoxConsultationServiceFactory
				.newInstance();
		this.ehBoxConsultationPort = service.getEhBoxConsultationPort();

		QName portQName = new QName(
				"urn:be:fgov:ehealth:ehbox:consultation:protocol:v2",
				"ehBoxConsultationPort");
		this.dispatch = service.createDispatch(portQName, Source.class,
				Service.Mode.PAYLOAD);

		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		configureBindingProvider((BindingProvider) this.ehBoxConsultationPort,
				location);
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

	public GetBoxInfoResponseType getBoxInfo(PrivateKey hokPrivateKey,
			String samlAssertion) throws BusinessError, SystemError {
		GetBoxInfoRequestType getBoxInfoRequest = new GetBoxInfoRequestType();
		this.wsSecuritySOAPHandler.setPrivateKey(hokPrivateKey);
		this.wsSecuritySOAPHandler.setAssertion(samlAssertion);
		GetBoxInfoResponseType getBoxInfoResponse = this.ehBoxConsultationPort
				.getBoxInfo(getBoxInfoRequest);
		return getBoxInfoResponse;
	}

	public Element invoke(Element request, PrivateKey hokPrivateKey,
			String samlAssertion) {
		this.wsSecuritySOAPHandler.setPrivateKey(hokPrivateKey);
		this.wsSecuritySOAPHandler.setAssertion(samlAssertion);
		Source responseSource = this.dispatch.invoke(new DOMSource(request));
		DOMSource responseDOMSource = (DOMSource) responseSource;
		Element responseElement = (Element) responseDOMSource.getNode();
		return responseElement;
	}
}
