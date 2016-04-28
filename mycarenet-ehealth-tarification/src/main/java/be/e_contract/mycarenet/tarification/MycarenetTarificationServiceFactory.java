/*
 * Java MyCareNet Project.
 * Copyright (C) 2016 e-Contract.be BVBA.
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

package be.e_contract.mycarenet.tarification;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.tarification.jaxws.MycarenetTarificationService;

public class MycarenetTarificationServiceFactory {

	private MycarenetTarificationServiceFactory() {
		super();
	}

	public static MycarenetTarificationService newInstance() {
		URL wsdlLocation = MycarenetTarificationServiceFactory.class.getResource("/MyCareNetTarification_v1.wsdl");
		QName MYCARENETTARIFICATIONSERVICE_QNAME = new QName("urn:be:fgov:ehealth:mycarenet:tarification:protocol:v1",
				"MycarenetTarificationService");
		MycarenetTarificationService service = new MycarenetTarificationService(wsdlLocation,
				MYCARENETTARIFICATIONSERVICE_QNAME);
		return service;
	}
}
