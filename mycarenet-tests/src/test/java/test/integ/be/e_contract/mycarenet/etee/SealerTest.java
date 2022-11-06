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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import be.e_contract.mycarenet.ehealth.common.EHealthKeyStore;
import be.e_contract.mycarenet.etee.Sealer;
import be.e_contract.mycarenet.etee.Unsealer;
import test.integ.be.e_contract.mycarenet.Config;

public class SealerTest {

	private static final Log LOG = LogFactory.getLog(SealerTest.class);

	private Config config;

	@BeforeAll
	public static void registerBC() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@BeforeEach
	public void setUp() throws Exception {
		this.config = new Config();
	}

	/**
	 * We seal a message targeted to ourselves.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSeal() throws Exception {
		FileInputStream keyStoreInputStream = new FileInputStream(this.config.getEHealthPKCS12Path());
		byte[] keyStoreData = IOUtils.toByteArray(keyStoreInputStream);
		String keyStorePassword = this.config.getEHealthPKCS12Password();
		EHealthKeyStore eHealthKeyStore = new EHealthKeyStore(keyStoreData, keyStorePassword);

		PrivateKey authenticationPrivateKey = eHealthKeyStore.getAuthenticationPrivateKey();
		X509Certificate authenticationCertificate = eHealthKeyStore.getAuthenticationCertificate();
		X509Certificate destinationCertificate = eHealthKeyStore.getEncryptionCertificate();

		List<X509Certificate> destinationCertificates = new LinkedList<>();
		destinationCertificates.add(destinationCertificate);
		destinationCertificates.add(destinationCertificate);
		Sealer sealer = new Sealer(authenticationPrivateKey, authenticationCertificate, destinationCertificates);

		byte[] message = "hello world".getBytes();

		byte[] sealedMessage = sealer.seal(message);
		assertNotNull(sealedMessage);

		Unsealer unsealer = new Unsealer(eHealthKeyStore.getEncryptionPrivateKey(),
				eHealthKeyStore.getEncryptionCertificate());

		byte[] unsealedData = unsealer.unseal(sealedMessage);

		assertArrayEquals(unsealedData, message);

		File sealFile = File.createTempFile("seal-fcorneli-", ".der");
		FileUtils.writeByteArrayToFile(sealFile, sealedMessage);
		LOG.debug("seal file: " + sealFile.getAbsolutePath());
	}
}
