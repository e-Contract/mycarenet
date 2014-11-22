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

package be.e_contract.mycarenet.sync;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.jaxws.sync.MyCarenetCareProviderSyncService;

public class MyCareNetSyncServiceFactory {

	private MyCareNetSyncServiceFactory() {
		super();
	}

	public static MyCarenetCareProviderSyncService newInstance() {
		URL wsdlLocation = MyCareNetSyncServiceFactory.class
				.getResource("/care-provider-sync.wsdl");
		QName serviceName = new QName("urn:be:cin:mycarenet:1.0:sync",
				"MyCarenetCareProviderSyncService");
		MyCarenetCareProviderSyncService service = new MyCarenetCareProviderSyncService(
				wsdlLocation, serviceName);
		return service;
	}
}
