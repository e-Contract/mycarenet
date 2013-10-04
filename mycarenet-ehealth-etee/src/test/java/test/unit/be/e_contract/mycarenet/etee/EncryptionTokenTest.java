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

package test.unit.be.e_contract.mycarenet.etee;

import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;
import org.junit.Test;

import be.e_contract.mycarenet.etee.EncryptionToken;

public class EncryptionTokenTest {

	private static final Log LOG = LogFactory.getLog(EncryptionTokenTest.class);

	@Test
	public void testReadEncryptionToken() throws Exception {
		InputStream etkInputStream = EncryptionTokenTest.class
				.getResourceAsStream("/etk-fcorneli.der");
		assertNotNull(etkInputStream);

		CMSSignedData cmsSignedData = new CMSSignedData(etkInputStream);
		LOG.debug("SignedData version: " + cmsSignedData.getVersion());

		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		LOG.debug("signers: " + signers.size());
		SignerInformation signer = (SignerInformation) signers.getSigners()
				.iterator().next();
		SignerId signerId = signer.getSID();
		LOG.debug("signer Id: " + signerId.getIssuer());

		Store certificateStore = cmsSignedData.getCertificates();
		Collection<X509CertificateHolder> certificateCollection = certificateStore
				.getMatches(signerId);
		X509CertificateHolder certificateHolder = certificateCollection
				.iterator().next();

		LOG.debug("certificate collection size: "
				+ certificateCollection.size());

		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificateHolder
						.getEncoded()));
		LOG.debug("signer certificate: " + certificate);

		CMSTypedData signedContent = cmsSignedData.getSignedContent();
		byte[] data = (byte[]) signedContent.getContent();

		X509Certificate encryptionCertificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(data));
		LOG.debug("encryption certificate: " + encryptionCertificate);
	}

	@Test
	public void testEncryptionToken() throws Exception {
		InputStream etkInputStream = EncryptionTokenTest.class
				.getResourceAsStream("/etk-fcorneli.der");
		byte[] data = IOUtils.toByteArray(etkInputStream);

		EncryptionToken encryptionToken = new EncryptionToken(data);
		X509Certificate encryptionCertificate = encryptionToken
				.getEncryptionCertificate();
		LOG.debug("encryption certificate: " + encryptionCertificate);
	}
}
