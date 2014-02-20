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

package be.e_contract.mycarenet.etee;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.bc.BcRSAKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

/**
 * eHealth end-to-end encryption unsealer implementation. This unsealer is
 * stateful as it keeps track of the sender certificate. The unsealer already
 * supports multiple recipients.
 * 
 * @author fcorneli
 * 
 */
public class Unsealer {

	private static final Log LOG = LogFactory.getLog(Unsealer.class);

	private final PrivateKey decryptionPrivateKey;

	private final X509Certificate decryptionCertificate;

	private X509Certificate senderCertificate;

	/**
	 * @param decryptionPrivateKey
	 *            the eHealth encryption private key.
	 * @param decryptionCertificate
	 *            used for automatic recipient selection
	 */
	public Unsealer(PrivateKey decryptionPrivateKey,
			X509Certificate decryptionCertificate) {
		this.decryptionPrivateKey = decryptionPrivateKey;
		this.decryptionCertificate = decryptionCertificate;
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
		@SuppressWarnings("unchecked")
		Collection<X509CertificateHolder> certificateCollection = certificateStore
				.getMatches(signerId);
		if (null == this.senderCertificate) {
			if (certificateCollection.isEmpty()) {
				throw new SecurityException("no sender certificate present");
			}
			X509CertificateHolder certificateHolder = certificateCollection
					.iterator().next();
			CertificateFactory certificateFactory = CertificateFactory
					.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(
							certificateHolder.getEncoded()));

			this.senderCertificate = certificate;
			LOG.debug("signer certificate subject: "
					+ certificate.getSubjectX500Principal());
		}

		/*
		 * By reusing the sender certificate we have the guarantee that the
		 * outer signature and inner signature share the same origin.
		 */
		SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
				.build(this.senderCertificate);
		boolean signatureResult = signer.verify(signerInformationVerifier);
		if (false == signatureResult) {
			throw new SecurityException("woops");
		}

		CMSTypedData signedContent = cmsSignedData.getSignedContent();
		byte[] data = (byte[]) signedContent.getContent();
		return data;
	}

	@SuppressWarnings("unchecked")
	private byte[] decrypt(byte[] encryptedData) throws CMSException,
			IOException {
		CMSEnvelopedDataParser cmsEnvelopedDataParser = new CMSEnvelopedDataParser(
				encryptedData);
		LOG.debug("content encryption algo: "
				+ cmsEnvelopedDataParser.getContentEncryptionAlgorithm()
						.getAlgorithm().getId());

		RecipientInformationStore recipientInformationStore = cmsEnvelopedDataParser
				.getRecipientInfos();
		RecipientId recipientId = new JceKeyTransRecipientId(
				this.decryptionCertificate);
		Collection<RecipientInformation> recipients = recipientInformationStore
				.getRecipients(recipientId);
		LOG.debug("number of recipients for given decryption cert: "
				+ recipients.size());
		if (0 == recipients.size()) {
			recipients = recipientInformationStore.getRecipients();
			LOG.debug("number of all recipients: " + recipients.size());
			Iterator<RecipientInformation> recipientsIterator = recipients
					.iterator();
			while (recipientsIterator.hasNext()) {
				RecipientInformation recipientInformation = recipientsIterator
						.next();
				RecipientId actualRecipientId = recipientInformation.getRID();
				LOG.debug("actual recipient id type: "
						+ actualRecipientId.getClass().getName());
				if (actualRecipientId instanceof KeyTransRecipientId) {
					KeyTransRecipientId actualKeyTransRecipientId = (KeyTransRecipientId) actualRecipientId;
					LOG.debug("actual recipient issuer: "
							+ actualKeyTransRecipientId.getIssuer());
					LOG.debug("actual recipient serial number: "
							+ actualKeyTransRecipientId.getSerialNumber());
				}
			}
			throw new SecurityException(
					"message does not seem to be addressed to you");
		}
		Iterator<RecipientInformation> recipientsIterator = recipients
				.iterator();
		RecipientInformation recipientInformation = recipientsIterator.next();

		AsymmetricKeyParameter privKeyParams = PrivateKeyFactory
				.createKey(this.decryptionPrivateKey.getEncoded());
		BcRSAKeyTransEnvelopedRecipient recipient = new BcRSAKeyTransEnvelopedRecipient(
				privKeyParams);
		byte[] decryptedContent = recipientInformation.getContent(recipient);
		return decryptedContent;
	}

	/**
	 * Unseals the given sealed data blob.
	 * 
	 * @param data
	 * @return
	 * @throws CertificateException
	 * @throws OperatorCreationException
	 * @throws CMSException
	 * @throws IOException
	 */
	public byte[] unseal(byte[] data) throws CertificateException,
			OperatorCreationException, CMSException, IOException {
		/*
		 * Only unseal when we actually received something.
		 */
		if (null == data) {
			return null;
		}
		if (0 == data.length) {
			return data;
		}
		byte[] encryptedData = getVerifiedContent(data);
		byte[] decryptedData = decrypt(encryptedData);
		byte[] unsealedData = getVerifiedContent(decryptedData);
		return unsealedData;
	}

	/**
	 * Gives back the eHealth authentication certificate of the sender of the
	 * sealed data.
	 * 
	 * @return
	 */
	public X509Certificate getSenderCertificate() {
		return this.senderCertificate;
	}
}
