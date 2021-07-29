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
package test.unit.be.e_contract.mycarenet.eh2box;

import be.e_contract.mycarenet.eh2ebox.EhBoxPublicationServiceFactory;
import be.e_contract.mycarenet.eh2ebox.jaxws.publication.EhBoxPublicationService;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class EhBoxPublicationServiceFactoryTest {

	@Test
	public void testNewInstance() throws Exception {
		EhBoxPublicationService service = EhBoxPublicationServiceFactory.newInstance();

		assertNotNull(service);
	}
}
