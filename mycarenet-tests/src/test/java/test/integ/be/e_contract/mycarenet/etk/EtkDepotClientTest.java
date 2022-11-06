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

package test.integ.be.e_contract.mycarenet.etk;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.mycarenet.etee.EncryptionToken;
import be.e_contract.mycarenet.etk.EtkDepotClient;
import be.fedict.commons.eid.client.BeIDCard;
import be.fedict.commons.eid.client.BeIDCards;
import be.fedict.commons.eid.client.FileType;
import be.fedict.commons.eid.consumer.Identity;
import be.fedict.commons.eid.consumer.tlv.TlvParser;

public class EtkDepotClientTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(EtkDepotClientTest.class);

	@Test
	public void testClient() throws Exception {
		EtkDepotClient etkDepotClient = new EtkDepotClient("https://services-acpt.ehealth.fgov.be/EtkDepot/v1");

		BeIDCards beIDCards = new BeIDCards();
		BeIDCard beIDCard = beIDCards.getOneBeIDCard();
		byte[] identityData = beIDCard.readFile(FileType.Identity);
		Identity identity = TlvParser.parse(identityData, Identity.class);

		String inss = identity.getNationalNumber();
		byte[] etk = etkDepotClient.getEtk("SSIN", inss);

		assertNotNull(etk);

		File tmpFile = File.createTempFile("etk-", ".der");
		FileUtils.writeByteArrayToFile(tmpFile, etk);
		LOGGER.debug("ETK file: {}", tmpFile.getAbsolutePath());

		EncryptionToken encryptionToken = new EncryptionToken(etk);

		X509Certificate encryptionCertificate = encryptionToken.getEncryptionCertificate();
		LOGGER.debug("encryption certificate issuer: {}", encryptionCertificate.getIssuerX500Principal());
		LOGGER.debug("encryption certificate subject: {}", encryptionCertificate.getSubjectX500Principal());

		X509Certificate authenticationCertificate = encryptionToken.getAuthenticationCertificate();
		LOGGER.debug("authentication certificate issuer: {}", authenticationCertificate.getIssuerX500Principal());
		LOGGER.debug("authentication certificate subject: {}", authenticationCertificate.getSubjectX500Principal());
	}

	@Test
	public void testScenario1() throws Exception {
		EtkDepotClient etkDepotClient = new EtkDepotClient("https://services-acpt.ehealth.fgov.be/EtkDepot/v1");

		byte[] etk = etkDepotClient.getEtk("NIHII-HOSPITAL", "71089815");
		assertNotNull(etk);
	}

	@Test
	public void testNonExitingSSIN() throws Exception {
		EtkDepotClient etkDepotClient = new EtkDepotClient("https://services-acpt.ehealth.fgov.be/EtkDepot/v1");

		byte[] etk = etkDepotClient.getEtk("SSIN", "23491519151");
		assertNull(etk);

		String payload = etkDepotClient.getPayload();
		LOGGER.debug("payload: {}", payload);
	}

	@Test
	public void testScenario2() throws Exception {
		EtkDepotClient etkDepotClient = new EtkDepotClient("https://services-acpt.ehealth.fgov.be/EtkDepot/v1");

		byte[] etk = etkDepotClient.getEtk("SSIN", "85040309180");
		assertNotNull(etk);

		etk = etkDepotClient.getEtk("CBE", "0809394427");
		assertNotNull(etk);

		etk = etkDepotClient.getEtk("NIHII-HOSPITAL", "71089815");
		assertNotNull(etk);

		etk = etkDepotClient.getEtk("NIHII-LABO", "89999964");
		assertNotNull(etk);
	}
}
