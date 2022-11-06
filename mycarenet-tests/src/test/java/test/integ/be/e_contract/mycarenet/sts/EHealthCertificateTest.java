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

package test.integ.be.e_contract.mycarenet.sts;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import test.integ.be.e_contract.mycarenet.Config;

public class EHealthCertificateTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(EHealthCertificateTest.class);

	private Config config;

	@BeforeEach
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testReadCertificate() throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		LOGGER.debug("eHealth PKCS12 path: {}", this.config.getEHealthPKCS12Path());
		FileInputStream fileInputStream = new FileInputStream(this.config.getEHealthPKCS12Path());
		keyStore.load(fileInputStream, this.config.getEHealthPKCS12Password().toCharArray());
		Enumeration<String> aliasesEnum = keyStore.aliases();
		while (aliasesEnum.hasMoreElements()) {
			String alias = aliasesEnum.nextElement();
			LOGGER.debug("alias: {}", alias);
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
			// LOG.debug("certificate: " + certificate);
			LOGGER.debug("certificate subject: {}", certificate.getSubjectX500Principal());

			X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());
			X500Name subjectName = certificateHolder.getSubject();
			RDN[] rdns = subjectName.getRDNs();
			for (RDN rdn : rdns) {
				LOGGER.debug("--------");
				AttributeTypeAndValue[] attributes = rdn.getTypesAndValues();
				for (AttributeTypeAndValue attribute : attributes) {
					LOGGER.debug("{} = {}", attribute.getType(), attribute.getValue());
					LOGGER.debug("value type: {}", attribute.getValue().getClass().getName());
				}
			}

			Certificate[] certificateChain = keyStore.getCertificateChain(alias);
			for (Certificate cert : certificateChain) {
				// LOG.debug("certificate chain: " + cert);
			}
		}
	}
}
