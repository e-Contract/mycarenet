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

package be.e_contract.mycarenet.ehealth.therlink;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.ehealth.therlink.jaxws.TherLinkService;

public class TherLinkServiceFactory {

	private TherLinkServiceFactory() {
		super();
	}

	public static TherLinkService newInstance() {
		URL wsdlLocation = TherLinkServiceFactory.class.getResource("/TherLink_v1.wsdl");
		QName THERLINKSERVICE_QNAME = new QName("urn:be:fgov:ehealth:therlink:protocol:v1", "TherLinkService");
		TherLinkService service = new TherLinkService(wsdlLocation, THERLINKSERVICE_QNAME);
		return service;
	}
}
