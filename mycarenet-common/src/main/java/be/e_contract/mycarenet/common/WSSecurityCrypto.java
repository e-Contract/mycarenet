/*
 * Java MyCareNet Project.
 * Copyright (C) 2012-2023 e-Contract.be BV.
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
package be.e_contract.mycarenet.common;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.regex.Pattern;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generic WSS4J Crypto implementation.
 *
 * @author Frank Cornelis
 *
 */
public class WSSecurityCrypto implements Crypto {

	private static final Logger LOGGER = LoggerFactory.getLogger(WSSecurityCrypto.class);

	private final PrivateKey privateKey;

	private final X509Certificate certificate;

	public WSSecurityCrypto(SessionKey sessionKey) {
		this.privateKey = sessionKey.getPrivate();
		this.certificate = sessionKey.getCertificate();
	}

	public WSSecurityCrypto(PrivateKey privateKey, X509Certificate certificate) {
		this.privateKey = privateKey;
		this.certificate = certificate;
	}

	@Override
	public byte[] getBytesFromCertificates(X509Certificate[] certs) throws WSSecurityException {
		LOGGER.debug("getBytesFromCertificates");
		return null;
	}

	@Override
	public CertificateFactory getCertificateFactory() throws WSSecurityException {
		LOGGER.debug("getCertificateFactory");
		return null;
	}

	@Override
	public X509Certificate[] getCertificatesFromBytes(byte[] data) throws WSSecurityException {
		LOGGER.debug("getCertificatesFromBytes");
		return null;
	}

	@Override
	public String getCryptoProvider() {
		LOGGER.debug("getCryptoProvider");
		return null;
	}

	@Override
	public String getDefaultX509Identifier() throws WSSecurityException {
		LOGGER.debug("getDefaultX509Identifier");
		return null;
	}

	@Override
	public PrivateKey getPrivateKey(X509Certificate certificate, CallbackHandler callbackHandler)
			throws WSSecurityException {
		LOGGER.debug("getPrivateKey(cert, callback)");
		return null;
	}

	@Override
	public PrivateKey getPrivateKey(String identifier, String password) throws WSSecurityException {
		LOGGER.debug("getPrivateKey(identifier, password)");
		return this.privateKey;
	}

	@Override
	public byte[] getSKIBytesFromCert(X509Certificate cert) throws WSSecurityException {
		LOGGER.debug("getSKIBytesFromCert");
		return null;
	}

	@Override
	public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException {
		LOGGER.debug("getX509Certificates");
		X509Certificate[] certificates = new X509Certificate[] { this.certificate };
		return certificates;
	}

	@Override
	public String getX509Identifier(X509Certificate cert) throws WSSecurityException {
		LOGGER.debug("getX509Identifier");
		return null;
	}

	@Override
	public X509Certificate loadCertificate(InputStream in) throws WSSecurityException {
		LOGGER.debug("loadCertificate");
		return null;
	}

	@Override
	public void setCryptoProvider(String provider) {
		LOGGER.debug("setCryptoProvider");
	}

	@Override
	public void setDefaultX509Identifier(String identifier) {
		LOGGER.debug("setDefaultX509Identifier");
	}

	@Override
	public void verifyTrust(PublicKey publicKey) throws WSSecurityException {
		LOGGER.debug("verifyTrust(publicKey)");
	}

	@Override
	public String getTrustProvider() {
		LOGGER.debug("getTrustProvider");
		return null;
	}

	@Override
	public void setTrustProvider(String provider) {
		LOGGER.debug("setTrustProvider: {}", provider);
	}

	@Override
	public void setCertificateFactory(CertificateFactory certFactory) {
		LOGGER.debug("setCertificateFactory");
	}

	@Override
	public PrivateKey getPrivateKey(PublicKey publicKey, CallbackHandler callbackHandler) throws WSSecurityException {
		LOGGER.debug("getPrivateKey");
		return null;
	}

	@Override
	public void verifyTrust(X509Certificate[] certs, boolean enableRevocation,
			Collection<Pattern> subjectCertConstraints, Collection<Pattern> issuerCertConstraints)
			throws WSSecurityException {
		LOGGER.debug("verifyTrust");
	}
}
