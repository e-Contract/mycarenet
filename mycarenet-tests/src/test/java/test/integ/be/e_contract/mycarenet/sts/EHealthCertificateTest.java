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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;

import test.integ.be.e_contract.mycarenet.Config;

public class EHealthCertificateTest {

	private static final Log LOG = LogFactory
			.getLog(EHealthCertificateTest.class);

	private Config config;

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testReadCertificate() throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		FileInputStream fileInputStream = new FileInputStream(
				this.config.getEHealthPKCS12Path());
		keyStore.load(fileInputStream, this.config.getEHealthPKCS12Password()
				.toCharArray());
		Enumeration<String> aliasesEnum = keyStore.aliases();
		while (aliasesEnum.hasMoreElements()) {
			String alias = aliasesEnum.nextElement();
			LOG.debug("alias: " + alias);
			X509Certificate certificate = (X509Certificate) keyStore
					.getCertificate(alias);
			LOG.debug("certificate: " + certificate);
			Certificate[] certificateChain = keyStore
					.getCertificateChain(alias);
			for (Certificate cert : certificateChain) {
				LOG.debug("certificate chain: " + cert);
			}
		}
	}
}
