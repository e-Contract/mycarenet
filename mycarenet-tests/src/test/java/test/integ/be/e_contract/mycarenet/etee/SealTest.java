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

package test.integ.be.e_contract.mycarenet.etee;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.bc.BcRSAKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.junit.Before;
import org.junit.Test;

import test.integ.be.e_contract.mycarenet.Config;

public class SealTest {

	private static final Log LOG = LogFactory.getLog(SealTest.class);

	private Config config;

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
		Security.addProvider(new BouncyCastleProvider());
	}

	private byte[] getVerifiedContent(byte[] cmsData)
			throws CertificateException, CMSException, IOException,
			OperatorCreationException {
		CMSSignedData cmsSignedData = new CMSSignedData(cmsData);
		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		SignerInformation signer = (SignerInformation) signers.getSigners()
				.iterator().next();
		SignerId signerId = signer.getSID();

		Store certificateStore = cmsSignedData.getCertificates();
		Collection<X509CertificateHolder> certificateCollection = certificateStore
				.getMatches(signerId);
		if (false == certificateCollection.isEmpty()) {
			X509CertificateHolder certificateHolder = certificateCollection
					.iterator().next();
			CertificateFactory certificateFactory = CertificateFactory
					.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(
							certificateHolder.getEncoded()));

			SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
					.build(certificate);
			boolean signatureResult = signer.verify(signerInformationVerifier);
			assertTrue(signatureResult);

			LOG.debug("signer certificate: " + certificate);
		} else {
			LOG.warn("no signer matched");
		}

		CMSTypedData signedContent = cmsSignedData.getSignedContent();
		byte[] data = (byte[]) signedContent.getContent();
		return data;
	}

	@Test
	public void testSeal() throws Exception {
		InputStream sealInputStream = SealTest.class
				.getResourceAsStream("/seal-fcorneli.der");
		assertNotNull(sealInputStream);
		byte[] cmsData = IOUtils.toByteArray(sealInputStream);

		// check outer signature
		byte[] data = getVerifiedContent(cmsData);

		// decrypt content

		CMSEnvelopedDataParser cmsEnvelopedDataParser = new CMSEnvelopedDataParser(
				data);
		LOG.debug("content encryption algo: "
				+ cmsEnvelopedDataParser.getContentEncryptionAlgorithm()
						.getAlgorithm().getId());

		RecipientInformationStore recipientInformationStore = cmsEnvelopedDataParser
				.getRecipientInfos();
		Collection<RecipientInformation> recipients = recipientInformationStore
				.getRecipients();
		RecipientInformation recipientInformation = recipients.iterator()
				.next();
		LOG.debug("recipient info type: "
				+ recipientInformation.getClass().getName());
		KeyTransRecipientInformation keyTransRecipientInformation = (KeyTransRecipientInformation) recipientInformation;

		// load eHealth encryption certificate
		KeyStore eHealthKeyStore = KeyStore.getInstance("PKCS12");
		FileInputStream fileInputStream = new FileInputStream(
				this.config.getEHealthPKCS12Path());
		eHealthKeyStore.load(fileInputStream, this.config
				.getEHealthPKCS12Password().toCharArray());
		Enumeration<String> aliasesEnum = eHealthKeyStore.aliases();
		aliasesEnum.nextElement(); // skip authentication certificate.
		String alias = aliasesEnum.nextElement();
		X509Certificate eHealthCertificate = (X509Certificate) eHealthKeyStore
				.getCertificate(alias);
		PrivateKey eHealthPrivateKey = (PrivateKey) eHealthKeyStore.getKey(
				alias, this.config.getEHealthPKCS12Password().toCharArray());

		AsymmetricKeyParameter privKeyParams = PrivateKeyFactory
				.createKey(eHealthPrivateKey.getEncoded());
		BcRSAKeyTransEnvelopedRecipient recipient = new BcRSAKeyTransEnvelopedRecipient(
				privKeyParams);
		byte[] decryptedContent = recipientInformation.getContent(recipient);
		assertNotNull(decryptedContent);
		LOG.debug("decrypted content size: " + decryptedContent.length);

		byte[] result = getVerifiedContent(decryptedContent);
		LOG.debug("result: " + new String(result));
	}
}
