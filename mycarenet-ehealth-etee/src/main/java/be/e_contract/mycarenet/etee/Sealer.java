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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class Sealer {

	private final PrivateKey authenticationPrivateKey;
	private final X509Certificate authenticationCertificate;
	private final X509Certificate destinationCertificate;

	public Sealer(PrivateKey authenticationPrivateKey,
			X509Certificate authenticationCertificate,
			X509Certificate destinationCertificate) {
		this.authenticationCertificate = authenticationCertificate;
		this.authenticationPrivateKey = authenticationPrivateKey;
		this.destinationCertificate = destinationCertificate;
	}

	public byte[] seal(byte[] data) throws OperatorCreationException,
			CertificateEncodingException, CMSException, IOException {
		byte[] innerSignedData = sign(data);
		byte[] encryptedData = encrypt(innerSignedData);
		byte[] outerSignedData = sign(encryptedData);
		return outerSignedData;
	}

	private byte[] encrypt(byte[] data) throws CertificateEncodingException,
			CMSException, IOException {
		CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
		cmsEnvelopedDataGenerator
				.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(
						this.destinationCertificate).setProvider("BC"));
		CMSTypedData cmsTypedData = new CMSProcessableByteArray(data);
		CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(
				cmsTypedData, new JceCMSContentEncryptorBuilder(
						CMSAlgorithm.AES128_CBC).setProvider("BC").build());
		return cmsEnvelopedData.getEncoded();
	}

	private byte[] sign(byte[] data) throws OperatorCreationException,
			CertificateEncodingException, CMSException, IOException {
		CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA")
				.setProvider("BC").build(this.authenticationPrivateKey);
		cmsSignedDataGenerator
				.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
						new JcaDigestCalculatorProviderBuilder().setProvider(
								"BC").build()).build(contentSigner,
						this.authenticationCertificate));
		cmsSignedDataGenerator.addCertificate(new X509CertificateHolder(
				this.authenticationCertificate.getEncoded()));
		CMSTypedData cmsTypedData = new CMSProcessableByteArray(data);
		CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(
				cmsTypedData, true);
		return cmsSignedData.getEncoded();
	}
}
