/*
 * Java MyCareNet Project.
 * Copyright (C) 2013-2022 e-Contract.be BV.
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

package test.unit.be.e_contract.mycarenet.etee;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

import be.e_contract.mycarenet.etee.Unsealer;

public class UnsealerTest {

	@Test
	public void testNullData() throws Exception {
		Unsealer unsealer = new Unsealer(null, null);
		assertNull(unsealer.unseal(null));
	}

	@Test
	public void testEmptyData() throws Exception {
		Unsealer unsealer = new Unsealer(null, null);
		byte[] result = unsealer.unseal(new byte[] {});
		assertNotNull(result);
		assertEquals(0, result.length);
	}
}
