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

package test.integ.be.e_contract.mycarenet.sts;

import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import test.integ.be.e_contract.mycarenet.Config;
import be.e_contract.mycarenet.ehealth.common.EHealthKeyStore;

public class EHealthKeyStoreTest {

	private Config config;

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testLoadKeyStore() throws Exception {
		FileInputStream fileInputStream = new FileInputStream(
				this.config.getEHealthPKCS12Path());
		byte[] keyStoreData = IOUtils.toByteArray(fileInputStream);
		EHealthKeyStore eHealthKeyStore = new EHealthKeyStore(keyStoreData,
				this.config.getEHealthPKCS12Password());

		assertNotNull(eHealthKeyStore.getAuthenticationCertificate());
		assertNotNull(eHealthKeyStore.getAuthenticationPrivateKey());
		assertNotNull(eHealthKeyStore.getEncryptionCertificate());
		assertNotNull(eHealthKeyStore.getEncryptionPrivateKey());
	}
}
