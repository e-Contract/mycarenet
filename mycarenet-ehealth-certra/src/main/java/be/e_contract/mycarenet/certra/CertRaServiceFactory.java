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

package be.e_contract.mycarenet.certra;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.certra.jaxws.CertRaService;

public class CertRaServiceFactory {

	private CertRaServiceFactory() {
		super();
	}

	/**
	 * Gives back a new instance of the CertRA JAX-WS service.
	 * 
	 * @return
	 */
	public static CertRaService newInstance() {
		URL wsdlLocation = CertRaServiceFactory.class.getResource("/certra-v1.wsdl");
		QName CERTRASERVICE_QNAME = new QName("urn:be:fgov:ehealth:certra:protocol:v1", "CertRaService");
		CertRaService service = new CertRaService(wsdlLocation, CERTRASERVICE_QNAME);
		return service;
	}
}
