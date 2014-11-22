/*
 * Java MyCareNet Project.
 * Copyright (C) 2012 e-Contract.be BVBA.
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

package be.e_contract.mycarenet.xkms;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.jaxws.xkms.XMLKeyManagementService;

public class XKMSServiceFactory {

	public static final String XKMS_NAMESPACE = "http://www.xkms.org/schema/xkms-2001-01-20";

	private XKMSServiceFactory() {
		super();
	}

	public static XMLKeyManagementService newInstance() {
		URL wsdlLocation = XKMSServiceFactory.class
				.getResource("/mycarenet-xkms.wsdl");
		QName serviceName = new QName(XKMS_NAMESPACE, "XMLKeyManagementService");
		XMLKeyManagementService service = new XMLKeyManagementService(
				wsdlLocation, serviceName);
		return service;
	}
}
