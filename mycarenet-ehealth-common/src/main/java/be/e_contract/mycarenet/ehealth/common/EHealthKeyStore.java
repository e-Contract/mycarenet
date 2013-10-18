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

package be.e_contract.mycarenet.ehealth.common;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * eHealth key store loader.
 * 
 * @author Frank Cornelis
 * 
 */
public class EHealthKeyStore {

	private final X509Certificate authenticationCertificate;
	private final PrivateKey authenticationPrivateKey;
	private final X509Certificate encryptionCertificate;
	private final PrivateKey encryptionPrivateKey;

	/**
	 * Main constructor.
	 * 
	 * @param keyStoreData
	 *            the PKCS#12 key store data.
	 * @param keyStorePassword
	 *            the PKCS#12 password.
	 */
	public EHealthKeyStore(byte[] keyStoreData, String keyStorePassword) {
		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("PKCS12");
		} catch (KeyStoreException e) {
			throw new RuntimeException("PKCS12 algo error: " + e.getMessage(),
					e);
		}
		InputStream keyStoreInputStream = new ByteArrayInputStream(keyStoreData);
		try {
			keyStore.load(keyStoreInputStream, keyStorePassword.toCharArray());
		} catch (Exception e) {
			throw new RuntimeException("error loading keystore: "
					+ e.getMessage(), e);
		}
		Enumeration<String> aliasesEnum;
		try {
			aliasesEnum = keyStore.aliases();
		} catch (KeyStoreException e) {
			throw new RuntimeException("error loading aliases: "
					+ e.getMessage(), e);
		}
		X509Certificate authnCertificate = null;
		PrivateKey authnPrivateKey = null;
		X509Certificate encryptionCertificate = null;
		PrivateKey encryptionPrivateKey = null;
		while (aliasesEnum.hasMoreElements()) {
			String alias = aliasesEnum.nextElement();
			X509Certificate certificate;
			try {
				certificate = (X509Certificate) keyStore.getCertificate(alias);
			} catch (KeyStoreException e) {
				throw new RuntimeException("error loading certificate: "
						+ e.getMessage(), e);
			}
			if (certificate.getKeyUsage()[0]) {
				// digital signature certificate
				authnCertificate = certificate;
				try {
					authnPrivateKey = (PrivateKey) keyStore.getKey(alias,
							keyStorePassword.toCharArray());
				} catch (Exception e) {
					throw new RuntimeException("error loading private key: "
							+ e.getMessage(), e);
				}
			} else {
				// encryption certificate
				encryptionCertificate = certificate;
				try {
					encryptionPrivateKey = (PrivateKey) keyStore.getKey(alias,
							keyStorePassword.toCharArray());
				} catch (Exception e) {
					throw new RuntimeException("error loading private key: "
							+ e.getMessage(), e);
				}
			}
		}
		this.authenticationCertificate = authnCertificate;
		this.authenticationPrivateKey = authnPrivateKey;
		this.encryptionCertificate = encryptionCertificate;
		this.encryptionPrivateKey = encryptionPrivateKey;
	}

	/**
	 * Gives back the eHealth authentication certificate.
	 * 
	 * @return
	 */
	public X509Certificate getAuthenticationCertificate() {
		return this.authenticationCertificate;
	}

	/**
	 * Gives back the eHealth authentication private key.
	 * 
	 * @return
	 */
	public PrivateKey getAuthenticationPrivateKey() {
		return this.authenticationPrivateKey;
	}

	/**
	 * Gives back the eHealth encryption certificate.
	 * 
	 * @return
	 */
	public X509Certificate getEncryptionCertificate() {
		return this.encryptionCertificate;
	}

	/**
	 * Gives back the eHealth encryption private key.
	 * 
	 * @return
	 */
	public PrivateKey getEncryptionPrivateKey() {
		return this.encryptionPrivateKey;
	}
}
