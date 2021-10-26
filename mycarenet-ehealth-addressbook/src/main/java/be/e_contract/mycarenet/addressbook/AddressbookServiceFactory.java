/*
 * Java MyCareNet Project.
 * Copyright (C) 2021 e-Contract.be BV.
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
package be.e_contract.mycarenet.addressbook;

import be.e_contract.mycarenet.addressbook.jaxws.AddressbookService;
import java.net.URL;
import javax.xml.namespace.QName;

public class AddressbookServiceFactory {

	private AddressbookServiceFactory() {
		super();
	}

	public static AddressbookService newInstance() {
		URL wsdlLocation = AddressbookServiceFactory.class.getResource("/addressbook-v1.wsdl");
		QName serviceName = new QName("urn:be:fgov:ehealth:addressbook:protocol:v1", "AddressbookService");
		AddressbookService service = new AddressbookService(wsdlLocation, serviceName);
		return service;
	}
}
