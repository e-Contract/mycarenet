/*
 * Java MyCareNet Project.
 * Copyright (C) 2020 e-Contract.be BV.
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

package be.e_contract.mycarenet.memberdata;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.memberdata.jaxws.MycarenetMemberDataService;

public class MycarenetMemberDataServiceFactory {

	private MycarenetMemberDataServiceFactory() {
		super();
	}

	public static MycarenetMemberDataService newInstance() {
		URL wsdlLocation = MycarenetMemberDataServiceFactory.class.getResource("/MyCareNetMemberData_v1.wsdl");
		QName MYCARENETMEMBERDATASERVICE_QNAME = new QName("urn:be:fgov:ehealth:mycarenet:memberdata:protocol:v1",
				"MycarenetMemberDataService");
		MycarenetMemberDataService service = new MycarenetMemberDataService(wsdlLocation,
				MYCARENETMEMBERDATASERVICE_QNAME);
		return service;
	}
}
