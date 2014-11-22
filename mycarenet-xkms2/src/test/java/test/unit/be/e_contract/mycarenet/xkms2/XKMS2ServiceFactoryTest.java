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

package test.unit.be.e_contract.mycarenet.xkms2;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import be.e_contract.mycarenet.jaxws.xkms2.XMLKeyManagementService;
import be.e_contract.mycarenet.xkms2.XKMS2ServiceFactory;

public class XKMS2ServiceFactoryTest {

	@Test
	public void testNewInstance() {
		// operate
		XMLKeyManagementService service = XKMS2ServiceFactory.newInstance();

		// verify
		assertNotNull(service);
	}
}
