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

package be.e_contract.mycarenet.vitalink.intrahub;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.vitalink.intrahub.jaxws.IntraHubService;

public class IntraHubServiceFactory {

	private IntraHubServiceFactory() {
		super();
	}

	/**
	 * Gives back a new instance of the IntraHubService JAX-WS service.
	 * 
	 * @return
	 */
	public static IntraHubService newInstance() {
		URL wsdlLocation = IntraHubServiceFactory.class.getResource("/IntraHubService.wsdl");
		QName INTRAHUBSERVICE_QNAME = new QName("http://www.ehealth.fgov.be/intrahub/protocol/v3", "IntraHubService");
		IntraHubService service = new IntraHubService(wsdlLocation, INTRAHUBSERVICE_QNAME);
		return service;
	}
}
