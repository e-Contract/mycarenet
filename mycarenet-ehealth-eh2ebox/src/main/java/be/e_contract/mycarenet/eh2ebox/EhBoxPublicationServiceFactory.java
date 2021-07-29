/*
 * Java MyCareNet Project.
 * Copyright (C) 2020-2021 e-Contract.be BV.
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
package be.e_contract.mycarenet.eh2ebox;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.eh2ebox.jaxws.publication.EhBoxPublicationService;

public class EhBoxPublicationServiceFactory {

	private EhBoxPublicationServiceFactory() {
		super();
	}

	public static EhBoxPublicationService newInstance() {
		URL wsdlLocation = EhBoxPublicationServiceFactory.class.getResource("/Eh2eBoxPublication_v3.wsdl");
		QName serviceName = new QName("urn:be:fgov:ehealth:ehbox:publication:protocol:v3", "ehBoxPublicationService");
		EhBoxPublicationService service = new EhBoxPublicationService(wsdlLocation, serviceName);
		return service;
	}
}
