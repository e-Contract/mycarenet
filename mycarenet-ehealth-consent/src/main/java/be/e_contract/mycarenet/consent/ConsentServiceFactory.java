/*
 * Java MyCareNet Project.
 * Copyright (C) 2017 e-Contract.be BVBA.
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

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.consent.jaxws.ConsentService;

public class ConsentServiceFactory {

	private ConsentServiceFactory() {
		super();
	}

	public static ConsentService newInstance() {
		URL wsdlLocation = ConsentService.class.getResource("/Consent_v1.wsdl");
		QName CONSENTSERVICE_QNAME = new QName("urn:be:fgov:ehealth:consent:protocol:v1", "ConsentService");
		ConsentService service = new ConsentService(wsdlLocation, CONSENTSERVICE_QNAME);
		return service;
	}
}
