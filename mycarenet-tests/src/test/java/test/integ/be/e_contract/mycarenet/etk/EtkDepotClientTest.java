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

package test.integ.be.e_contract.mycarenet.etk;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.e_contract.mycarenet.etee.EncryptionToken;
import be.e_contract.mycarenet.etk.EtkDepotClient;
import be.fedict.commons.eid.client.BeIDCard;
import be.fedict.commons.eid.client.BeIDCards;
import be.fedict.commons.eid.client.FileType;
import be.fedict.commons.eid.consumer.Identity;
import be.fedict.commons.eid.consumer.tlv.TlvParser;

public class EtkDepotClientTest {

	private static final Log LOG = LogFactory.getLog(EtkDepotClientTest.class);

	@Test
	public void testClient() throws Exception {
		EtkDepotClient etkDepotClient = new EtkDepotClient(
				"https://wwwacc.ehealth.fgov.be/etkdepot_1_0/EtkDepotService");

		BeIDCards beIDCards = new BeIDCards();
		BeIDCard beIDCard = beIDCards.getOneBeIDCard();
		byte[] identityData = beIDCard.readFile(FileType.Identity);
		Identity identity = TlvParser.parse(identityData, Identity.class);

		String inss = identity.getNationalNumber();
		byte[] etk = etkDepotClient.getEtk(inss);

		assertNotNull(etk);

		File tmpFile = File.createTempFile("etk-", ".der");
		FileUtils.writeByteArrayToFile(tmpFile, etk);
		LOG.debug("ETK file: " + tmpFile.getAbsolutePath());

		EncryptionToken encryptionToken = new EncryptionToken(etk);

		X509Certificate encryptionCertificate = encryptionToken
				.getEncryptionCertificate();
		LOG.debug("encryption certificate issuer: "
				+ encryptionCertificate.getIssuerX500Principal());
		LOG.debug("encryption certificate subject: "
				+ encryptionCertificate.getSubjectX500Principal());

		X509Certificate authenticationCertificate = encryptionToken
				.getAuthenticationCertificate();
		LOG.debug("authentication certificate issuer: "
				+ authenticationCertificate.getIssuerX500Principal());
		LOG.debug("authentication certificate subject: "
				+ authenticationCertificate.getSubjectX500Principal());
	}
}
