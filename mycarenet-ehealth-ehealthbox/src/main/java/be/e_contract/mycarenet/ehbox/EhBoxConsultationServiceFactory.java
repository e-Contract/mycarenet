/*
 * Java MyCareNet Project.
 * Copyright (C) 2013 Frank Cornelis.
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

package be.e_contract.mycarenet.ehbox;

import java.net.URL;

import javax.xml.namespace.QName;

import be.e_contract.mycarenet.ehbox.jaxws.consultation.EhBoxConsultationService;

public class EhBoxConsultationServiceFactory {

	private EhBoxConsultationServiceFactory() {
		super();
	}

	public static EhBoxConsultationService newInstance() {
		URL wsdlLocation = EhBoxConsultationServiceFactory.class
				.getResource("/ehBoxConsultation-v3.wsdl");
		QName serviceName = new QName(
				"urn:be:fgov:ehealth:ehbox:consultation:protocol:v3",
				"ehBoxConsultationService");
		EhBoxConsultationService service = new EhBoxConsultationService(
				wsdlLocation, serviceName);
		return service;
	}
}
