/*
 * Java MyCareNet Project.
 * Copyright (C) 2013 e-Contract.be BVBA.
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

package be.e_contract.mycarenet.sts;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.jaxws.sts.EHealthSamlStsService;

public class EHealthSamlStsServiceFactory {

	private EHealthSamlStsServiceFactory() {
		super();
	}

	public static EHealthSamlStsService newInstance() {
		URL wsdlLocation = EHealthSamlStsServiceFactory.class
				.getResource("/ehealth-saml-sts.wsdl");
		QName serviceName = new QName("urn:be:ehealth:saml:sts:1.0",
				"EHealthSamlStsService");
		EHealthSamlStsService service = new EHealthSamlStsService(wsdlLocation,
				serviceName);
		return service;
	}
}
