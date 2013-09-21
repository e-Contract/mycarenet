/*
 * Java MyCareNet Project.
 * Copyright (C) 2012 Frank Cornelis.
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

package be.e_contract.mycarenet.xkms2;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.jaxws.xkms2.XMLKeyManagementService;

public class XKMS2ServiceFactory {

	public static final String XKMS2_NAMESPACE = "http://www.w3.org/2002/03/xkms#";

	private XKMS2ServiceFactory() {
		super();
	}

	public static XMLKeyManagementService newInstance() {
		URL wsdlLocation = XKMS2ServiceFactory.class.getResource("/xkms2.wsdl");
		QName serviceName = new QName(XKMS2_NAMESPACE,
				"XMLKeyManagementService");
		XMLKeyManagementService service = new XMLKeyManagementService(
				wsdlLocation, serviceName);
		return service;
	}
}
