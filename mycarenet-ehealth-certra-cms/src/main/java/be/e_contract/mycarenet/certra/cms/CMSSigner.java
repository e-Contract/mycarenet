/*
 * Java MyCareNet Project.
 * Copyright (C) 2016 e-Contract.be BVBA.
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

package be.e_contract.mycarenet.certra.cms;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import be.e_contract.mycarenet.certra.cms.revoke.ObjectFactory;
import be.e_contract.mycarenet.certra.cms.revoke.RevocableCertificatesDataRequest;

public class CMSSigner {

	private final PrivateKey privateKey;

	private final List<X509Certificate> certificateChain;

	public CMSSigner(PrivateKey privateKey, List<X509Certificate> certificateChain) {
		this.privateKey = privateKey;
		this.certificateChain = certificateChain;
	}

	public byte[] sign(RevocableCertificatesDataRequest request) throws SignatureException {
		try {
			JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
			Marshaller marshaller = jaxbContext.createMarshaller();
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			marshaller.marshal(request, outputStream);

			CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
			ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(this.privateKey);
			cmsSignedDataGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build())
							.build(contentSigner, this.certificateChain.get(0)));
			for (X509Certificate certificate : this.certificateChain) {
				cmsSignedDataGenerator.addCertificate(new X509CertificateHolder(certificate.getEncoded()));
			}
			CMSTypedData cmsTypedData = new CMSProcessableByteArray(outputStream.toByteArray());
			CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(cmsTypedData, true);
			return cmsSignedData.getEncoded();

		} catch (Exception e) {
			throw new SignatureException(e);
		}
	}
}
