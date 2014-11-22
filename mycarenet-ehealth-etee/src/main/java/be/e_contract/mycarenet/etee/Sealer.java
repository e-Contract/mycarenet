/*
 * Java MyCareNet Project.
 * Copyright (C) 2013 e-Contract.be BVBA.
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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * eHealth end-to-end encryption sealer implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class Sealer {

	private final PrivateKey authenticationPrivateKey;
	private final X509Certificate authenticationCertificate;
	private final List<X509Certificate> destinationCertificates;

	public Sealer(PrivateKey authenticationPrivateKey,
			X509Certificate authenticationCertificate,
			X509Certificate destinationCertificate) {
		this.authenticationCertificate = authenticationCertificate;
		this.authenticationPrivateKey = authenticationPrivateKey;
		this.destinationCertificates = Collections
				.singletonList(destinationCertificate);
	}

	/**
	 * Main constructor.
	 * 
	 * @param authenticationPrivateKey
	 *            the eHealth authentication private key of the sender.
	 * @param authenticationCertificate
	 *            the eHealth authentication certificate of the sender.
	 * @param destinationCertificates
	 *            the eHealth encryption certificates of the recipients.
	 */
	public Sealer(PrivateKey authenticationPrivateKey,
			X509Certificate authenticationCertificate,
			List<X509Certificate> destinationCertificates) {
		this.authenticationCertificate = authenticationCertificate;
		this.authenticationPrivateKey = authenticationPrivateKey;
		this.destinationCertificates = destinationCertificates;
	}

	/**
	 * Seals the given data.
	 * 
	 * @param data
	 * @return
	 * @throws OperatorCreationException
	 * @throws CertificateEncodingException
	 * @throws CMSException
	 * @throws IOException
	 */
	public byte[] seal(byte[] data) throws OperatorCreationException,
			CertificateEncodingException, CMSException, IOException {
		byte[] innerSignedData = sign(data, false);
		byte[] encryptedData = encrypt(innerSignedData);
		byte[] outerSignedData = sign(encryptedData, true);
		return outerSignedData;
	}

	private byte[] encrypt(byte[] data) throws CertificateEncodingException,
			CMSException, IOException {
		CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
		for (X509Certificate destinationCertificate : this.destinationCertificates) {
			cmsEnvelopedDataGenerator
					.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(
							destinationCertificate)
							.setProvider(BouncyCastleProvider.PROVIDER_NAME));
		}
		CMSTypedData cmsTypedData = new CMSProcessableByteArray(data);
		CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(
				cmsTypedData,
				new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
						.setProvider(BouncyCastleProvider.PROVIDER_NAME)
						.build());
		return cmsEnvelopedData.getEncoded();
	}

	private byte[] sign(byte[] data, boolean includeCertificate)
			throws OperatorCreationException, CertificateEncodingException,
			CMSException, IOException {
		CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
				.find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
				.find(sigAlgId);
		AsymmetricKeyParameter privKeyParams = PrivateKeyFactory
				.createKey(this.authenticationPrivateKey.getEncoded());
		ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId,
				digAlgId).build(privKeyParams);
		cmsSignedDataGenerator
				.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
						new JcaDigestCalculatorProviderBuilder().setProvider(
								BouncyCastleProvider.PROVIDER_NAME).build())
						.build(contentSigner, this.authenticationCertificate));
		if (includeCertificate) {
			cmsSignedDataGenerator.addCertificate(new X509CertificateHolder(
					this.authenticationCertificate.getEncoded()));
		}
		CMSTypedData cmsTypedData = new CMSProcessableByteArray(data);
		CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(
				cmsTypedData, true);
		return cmsSignedData.getEncoded();
	}
}
