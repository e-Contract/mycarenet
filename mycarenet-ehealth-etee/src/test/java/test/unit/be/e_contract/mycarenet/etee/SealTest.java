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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SealTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(SealTest.class);

	@Test
	public void testSeal() throws Exception {
		InputStream sealInputStream = SealTest.class.getResourceAsStream("/seal-fcorneli.der");
		assertNotNull(sealInputStream);

		// check outer signature

		CMSSignedData cmsSignedData = new CMSSignedData(sealInputStream);
		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		SignerInformation signer = (SignerInformation) signers.getSigners().iterator().next();
		SignerId signerId = signer.getSID();

		Store certificateStore = cmsSignedData.getCertificates();
		@SuppressWarnings("unchecked")
		Collection<X509CertificateHolder> certificateCollection = certificateStore.getMatches(signerId);
		X509CertificateHolder certificateHolder = certificateCollection.iterator().next();
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificateHolder.getEncoded()));

		Security.addProvider(new BouncyCastleProvider());
		SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
				.build(certificate);
		boolean signatureResult = signer.verify(signerInformationVerifier);
		assertTrue(signatureResult);

		LOGGER.debug("signer certificate: {}", certificate);

		CMSTypedData signedContent = cmsSignedData.getSignedContent();
		byte[] data = (byte[]) signedContent.getContent();

		// decrypt content

		CMSEnvelopedDataParser cmsEnvelopedDataParser = new CMSEnvelopedDataParser(data);
		LOGGER.debug("content encryption algo: {}",
				cmsEnvelopedDataParser.getContentEncryptionAlgorithm().getAlgorithm().getId());

		RecipientInformationStore recipientInformationStore = cmsEnvelopedDataParser.getRecipientInfos();
		@SuppressWarnings("unchecked")
		Collection<RecipientInformation> recipients = recipientInformationStore.getRecipients();
		RecipientInformation recipientInformation = recipients.iterator().next();
		LOGGER.debug("recipient info type: {}", recipientInformation.getClass().getName());
		KeyTransRecipientInformation keyTransRecipientInformation = (KeyTransRecipientInformation) recipientInformation;

	}
}
