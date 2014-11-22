/*
 * Java MyCareNet Project.
 * Copyright (C) 2013-2014 e-Contract.be BVBA.
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

package test.integ.be.e_contract.mycarenet.etee;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Security;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import test.integ.be.e_contract.mycarenet.Config;
import be.e_contract.mycarenet.ehealth.common.EHealthKeyStore;
import be.e_contract.mycarenet.etee.Unsealer;

public class UnsealerTest {

	private static final Log LOG = LogFactory.getLog(UnsealerTest.class);

	private Config config;

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testUnsealing() throws Exception {
		InputStream sealInputStream = SealTest.class
				.getResourceAsStream("/seal-fcorneli.der");
		assertNotNull(sealInputStream);
		byte[] sealedData = IOUtils.toByteArray(sealInputStream);

		FileInputStream keyStoreInputStream = new FileInputStream(
				this.config.getEHealthPKCS12Path());
		byte[] keyStoreData = IOUtils.toByteArray(keyStoreInputStream);
		String keyStorePassword = this.config.getEHealthPKCS12Password();
		EHealthKeyStore eHealthKeyStore = new EHealthKeyStore(keyStoreData,
				keyStorePassword);

		Unsealer unsealer = new Unsealer(
				eHealthKeyStore.getEncryptionPrivateKey(),
				eHealthKeyStore.getEncryptionCertificate());

		try {
			unsealer.unseal(sealedData);
			fail();
		} catch (SecurityException e) {
			// expected
			LOG.debug(e.getMessage());
		}
	}

	@Test
	public void testUnsealing2014() throws Exception {
		InputStream sealInputStream = SealTest.class
				.getResourceAsStream("/seal-fcorneli-2014.der");
		assertNotNull(sealInputStream);
		byte[] sealedData = IOUtils.toByteArray(sealInputStream);

		FileInputStream keyStoreInputStream = new FileInputStream(
				this.config.getEHealthPKCS12Path());
		byte[] keyStoreData = IOUtils.toByteArray(keyStoreInputStream);
		String keyStorePassword = this.config.getEHealthPKCS12Password();
		EHealthKeyStore eHealthKeyStore = new EHealthKeyStore(keyStoreData,
				keyStorePassword);

		Unsealer unsealer = new Unsealer(
				eHealthKeyStore.getEncryptionPrivateKey(),
				eHealthKeyStore.getEncryptionCertificate());

		byte[] unsealedData = unsealer.unseal(sealedData);
		LOG.debug("unsealed data: " + new String(unsealedData));
		LOG.debug("sender certificate: " + unsealer.getSenderCertificate());
		assertEquals(unsealer.getSenderCertificate(),
				eHealthKeyStore.getAuthenticationCertificate());
	}
}
