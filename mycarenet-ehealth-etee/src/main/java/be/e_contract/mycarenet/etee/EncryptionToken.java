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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

public class EncryptionToken {

	private X509Certificate encryptionCertificate;

	public EncryptionToken(byte[] encodedEncryptionToken) {
		try {
			this.encryptionCertificate = parseEncryptionCertificate(encodedEncryptionToken);
		} catch (Exception e) {
			throw new RuntimeException("CMS error: " + e.getMessage(), e);
		}
	}

	/**
	 * Parse the encryption certificate from the CMS data structure. No need to
	 * check the CMS integrity as we just received it from the ETK anyway.
	 * 
	 * @param encodedEncryptionToken
	 * @return
	 * @throws CMSException
	 * @throws CertificateException
	 * @throws IOException
	 */
	private X509Certificate parseEncryptionCertificate(
			byte[] encodedEncryptionToken) throws CMSException,
			CertificateException, IOException {
		CMSSignedData cmsSignedData = new CMSSignedData(encodedEncryptionToken);
		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		SignerInformation signer = (SignerInformation) signers.getSigners()
				.iterator().next();
		SignerId signerId = signer.getSID();

		Store certificateStore = cmsSignedData.getCertificates();
		Collection<X509CertificateHolder> certificateCollection = certificateStore
				.getMatches(signerId);
		X509CertificateHolder certificateHolder = certificateCollection
				.iterator().next();
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificateHolder
						.getEncoded()));

		CMSTypedData signedContent = cmsSignedData.getSignedContent();
		byte[] data = (byte[]) signedContent.getContent();

		X509Certificate encryptionCertificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(data));
		return encryptionCertificate;
	}

	public X509Certificate getEncryptionCertificate() {
		return this.encryptionCertificate;
	}
}
