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
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

public class EncryptionToken {

	private static final Log LOG = LogFactory.getLog(EncryptionToken.class);

	private X509Certificate encryptionCertificate;

	private X509Certificate authenticationCertificate;

	public EncryptionToken(byte[] encodedEncryptionToken) {
		try {
			this.encryptionCertificate = parseEncryptionCertificate(encodedEncryptionToken);
		} catch (Exception e) {
			throw new RuntimeException("CMS error: " + e.getMessage(), e);
		}
	}

	private X509Certificate parseEncryptionCertificate(
			byte[] encodedEncryptionToken) throws CMSException,
			CertificateException, IOException, OperatorCreationException {
		CMSSignedData cmsSignedData = new CMSSignedData(encodedEncryptionToken);

		// get signer identifier
		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		SignerInformation signer = (SignerInformation) signers.getSigners()
				.iterator().next();
		SignerId signerId = signer.getSID();

		// get signer certificate
		Store certificateStore = cmsSignedData.getCertificates();
		LOG.debug("certificate store type: "
				+ certificateStore.getClass().getName());
		Collection<X509CertificateHolder> signingCertificateCollection = certificateStore
				.getMatches(signerId);
		X509CertificateHolder signingCertificateHolder = signingCertificateCollection
				.iterator().next();
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		X509Certificate signingCertificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(
						signingCertificateHolder.getEncoded()));
		LOG.debug("signing certificate: "
				+ signingCertificate.getSubjectX500Principal());

		// verify CMS signature
		SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
				.build(signingCertificate);
		boolean signatureResult = signer.verify(signerInformationVerifier);
		if (false == signatureResult) {
			throw new SecurityException("ETK signature invalid");
		}

		// get encryption certificate
		CMSTypedData signedContent = cmsSignedData.getSignedContent();
		byte[] data = (byte[]) signedContent.getContent();
		X509Certificate encryptionCertificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(data));

		LOG.debug("all available certificates:");
		logCertificates(certificateStore, null);

		// get authentication certificate
		CustomSelector authenticationSelector = new CustomSelector();
		authenticationSelector.setSubject(encryptionCertificate
				.getIssuerX500Principal());
		Collection<X509CertificateHolder> authenticationCertificates = certificateStore
				.getMatches(authenticationSelector);
		if (authenticationCertificates.size() != 1) {
			LOG.debug("no authentication certificate match");
		}
		X509CertificateHolder authenticationCertificateHolder = authenticationCertificates
				.iterator().next();
		this.authenticationCertificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(
						authenticationCertificateHolder.getEncoded()));

		verifyProxyCertificate(encryptionCertificate,
				this.authenticationCertificate);

		return encryptionCertificate;
	}

	/**
	 * RFC 3820
	 * 
	 * @param certificate
	 * @param issuer
	 */
	private void verifyProxyCertificate(X509Certificate certificate,
			X509Certificate issuer) {
		try {
			certificate.verify(issuer.getPublicKey());
			issuer.checkValidity();
		} catch (Exception e) {
			throw new SecurityException("not a proxy certificate");
		}
	}

	private void logCertificates(Store store, Selector selector) {
		Collection<X509CertificateHolder> certificates = store
				.getMatches(selector);
		LOG.debug("match size: " + certificates.size());
		Iterator<X509CertificateHolder> certificatesIterator = certificates
				.iterator();
		while (certificatesIterator.hasNext()) {
			X509CertificateHolder certificateHolder = certificatesIterator
					.next();
			LOG.debug("certificate issuer: " + certificateHolder.getIssuer());
			LOG.debug("certificate subject: " + certificateHolder.getSubject());
		}
	}

	private static class CustomSelector implements Selector {

		private X500Name subject;

		public void setSubject(X500Principal principal) {
			this.subject = new X500Name(principal.getName());
		}

		@Override
		public boolean match(Object object) {
			if (false == object instanceof X509CertificateHolder) {
				return false;
			}
			X509CertificateHolder certificateHolder = (X509CertificateHolder) object;
			return certificateHolder.getSubject().equals(this.subject);
		}

		public Object clone() {
			return this;
		}
	}

	public X509Certificate getEncryptionCertificate() {
		return this.encryptionCertificate;
	}

	public X509Certificate getAuthenticationCertificate() {
		return this.authenticationCertificate;
	}
}
