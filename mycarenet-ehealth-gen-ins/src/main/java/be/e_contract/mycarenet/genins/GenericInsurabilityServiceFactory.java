/*
 * Java MyCareNet Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.genins.jaxws.GenericInsurabilityService;

public class GenericInsurabilityServiceFactory {

	private GenericInsurabilityServiceFactory() {
		super();
	}

	/**
	 * Gives back a new instance of the GenIns JAX-WS service.
	 * 
	 * @return
	 */
	public static GenericInsurabilityService newInstance() {
		URL wsdlLocation = GenericInsurabilityServiceFactory.class
				.getResource("/GenericInsurabilityWebService-1_0.wsdl");
		QName GENERICINSURABILITYSERVICE_QNAME = new QName(
				"urn:be:fgov:ehealth:genericinsurability:protocol:v1",
				"GenericInsurabilityService");
		GenericInsurabilityService service = new GenericInsurabilityService(
				wsdlLocation, GENERICINSURABILITYSERVICE_QNAME);
		return service;
	}
}
