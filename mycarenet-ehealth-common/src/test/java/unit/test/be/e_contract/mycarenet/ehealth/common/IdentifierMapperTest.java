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

package unit.test.be.e_contract.mycarenet.ehealth.common;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import be.e_contract.mycarenet.ehealth.common.IdentifierMapper;

public class IdentifierMapperTest {

	@Test
	public void testMapping() throws Exception {
		assertEquals("SSIN",
				IdentifierMapper.getETKIdentifierType("INSS", "DOCTOR"));
		assertEquals("NIHII",
				IdentifierMapper.getETKIdentifierType("NIHII", "DOCTOR"));
		assertEquals("SSIN",
				IdentifierMapper.getETKIdentifierType("INSS", "NURSE"));
		assertEquals("NIHII",
				IdentifierMapper.getETKIdentifierType("NIHII", "NURSE"));
		assertEquals("SSIN",
				IdentifierMapper.getETKIdentifierType("INSS", "PRACTICALNURSE"));
		assertEquals("NIHII", IdentifierMapper.getETKIdentifierType("NIHII",
				"PRACTICALNURSE"));
		assertEquals("SSIN",
				IdentifierMapper.getETKIdentifierType("INSS", "DENTIST"));
		assertEquals("NIHII",
				IdentifierMapper.getETKIdentifierType("NIHII", "DENTIST"));
		assertEquals("NIHII-HOSPITAL",
				IdentifierMapper.getETKIdentifierType("NIHII", "HOSPITAL"));
		assertEquals("NIHII-PHARMACY",
				IdentifierMapper.getETKIdentifierType("FAMPH", "PHARMACY"));
		assertEquals("NIHII-LABO",
				IdentifierMapper.getETKIdentifierType("NIHII", "LABO"));
		assertEquals("NIHII-RETIREMENT",
				IdentifierMapper.getETKIdentifierType("NIHII", "RETIREMENT"));
		assertEquals("NIHII-OTD_PHARMACY",
				IdentifierMapper.getETKIdentifierType("NIHII", "OTD_PHARMACY"));
		assertEquals("NIHII-GROUP",
				IdentifierMapper.getETKIdentifierType("NIHII", "GROUP"));
		assertEquals("CBE",
				IdentifierMapper.getETKIdentifierType("CBE", "INSTITUTION"));
	}
}
