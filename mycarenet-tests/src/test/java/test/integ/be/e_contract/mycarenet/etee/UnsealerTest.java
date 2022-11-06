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

package test.integ.be.e_contract.mycarenet.etee;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Security;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.mycarenet.ehealth.common.EHealthKeyStore;
import be.e_contract.mycarenet.etee.Unsealer;
import test.integ.be.e_contract.mycarenet.Config;

public class UnsealerTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(UnsealerTest.class);

	private Config config;

	@BeforeAll
	public static void registerBC() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@BeforeEach
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testUnsealing() throws Exception {
		InputStream sealInputStream = SealTest.class.getResourceAsStream("/seal-fcorneli.der");
		assertNotNull(sealInputStream);
		byte[] sealedData = IOUtils.toByteArray(sealInputStream);

		FileInputStream keyStoreInputStream = new FileInputStream(this.config.getEHealthPKCS12Path());
		byte[] keyStoreData = IOUtils.toByteArray(keyStoreInputStream);
		String keyStorePassword = this.config.getEHealthPKCS12Password();
		EHealthKeyStore eHealthKeyStore = new EHealthKeyStore(keyStoreData, keyStorePassword);

		Unsealer unsealer = new Unsealer(eHealthKeyStore.getEncryptionPrivateKey(),
				eHealthKeyStore.getEncryptionCertificate());

		try {
			unsealer.unseal(sealedData);
			fail();
		} catch (SecurityException e) {
			// expected
			LOGGER.debug(e.getMessage());
		}
	}

	@Test
	public void testUnsealing2014() throws Exception {
		InputStream sealInputStream = SealTest.class.getResourceAsStream("/seal-fcorneli-2014.der");
		assertNotNull(sealInputStream);
		byte[] sealedData = IOUtils.toByteArray(sealInputStream);

		FileInputStream keyStoreInputStream = new FileInputStream(this.config.getEHealthPKCS12Path());
		byte[] keyStoreData = IOUtils.toByteArray(keyStoreInputStream);
		String keyStorePassword = this.config.getEHealthPKCS12Password();
		EHealthKeyStore eHealthKeyStore = new EHealthKeyStore(keyStoreData, keyStorePassword);

		Unsealer unsealer = new Unsealer(eHealthKeyStore.getEncryptionPrivateKey(),
				eHealthKeyStore.getEncryptionCertificate());

		byte[] unsealedData = unsealer.unseal(sealedData);
		LOGGER.debug("unsealed data: {}", new String(unsealedData));
		LOGGER.debug("sender certificate: {}", unsealer.getSenderCertificate());
		assertEquals(unsealer.getSenderCertificate(), eHealthKeyStore.getAuthenticationCertificate());
	}
}
