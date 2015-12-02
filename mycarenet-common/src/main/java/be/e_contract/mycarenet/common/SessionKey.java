/*
 * Java MyCareNet Project.
 * Copyright (C) 2012 e-Contract.be BVBA.
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

/**
 * MyCareNet session key.
 * 
 * @author Frank Cornelis
 * 
 */
public class SessionKey {

	private static final Log LOG = LogFactory.getLog(SessionKey.class);

	private static final int KEY_SIZE = 1024;

	private static final String DEFAULT_NAME = "CN=MyCarenetSessionKey, O=MyCareNet, C=BE";

	private final KeyPair keyPair;

	private Date notBefore;

	private Date notAfter;

	private X509Certificate certificate;

	private String name = DEFAULT_NAME;

	public SessionKey() {
		this(KEY_SIZE);
	}

	/**
	 * Generator constructor. Creates a new MyCareNet session key.
	 * 
	 * @param keySize
	 *            the RSA key size.
	 */
	public SessionKey(int keySize) {
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("RSA algo not available", e);
		}
		SecureRandom random = new SecureRandom();
		try {
			keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize,
					RSAKeyGenParameterSpec.F4), random);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException("unsupported key size: " + keySize);
		}
		this.keyPair = keyPairGenerator.generateKeyPair();
	}

	/**
	 * Loader constructor. Loads an existing MyCareNet session key.
	 * 
	 * @param encodedPrivateKey
	 * @param encodedPublicKey
	 * @param encodedCertificate
	 * @param notBefore
	 * @param notAfter
	 */
	public SessionKey(byte[] encodedPrivateKey, byte[] encodedPublicKey,
			byte[] encodedCertificate, Date notBefore, Date notAfter) {
		this.notBefore = notBefore;
		this.notAfter = notAfter;

		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("RSA", e);
		}
		PublicKey publicKey;
		try {
			publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("invalid public key: " + e.getMessage(),
					e);
		}

		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		PrivateKey privateKey;
		try {
			privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(
					"invalid private key: " + e.getMessage(), e);
		}

		this.keyPair = new KeyPair(publicKey, privateKey);

		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
		try {
			this.certificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(
							encodedCertificate));
		} catch (CertificateException e) {
			throw new RuntimeException("certificate decoding error: "
					+ e.getMessage(), e);
		}
	}

	/**
	 * Sets the distinguished name to be used on the generated self-signed
	 * certificate.
	 * 
	 * @param name
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Gives back the RSA modulus.
	 * 
	 * @return
	 */
	public byte[] getModulus() {
		RSAPublicKey rsaPublicKey = getRSAPublicKey();
		return rsaPublicKey.getModulus().toByteArray();
	}

	/**
	 * Gives back the RSA public modulus.
	 * 
	 * @return
	 */
	public byte[] getExponent() {
		RSAPublicKey rsaPublicKey = getRSAPublicKey();
		return rsaPublicKey.getPublicExponent().toByteArray();
	}

	/**
	 * Gives back the RSA public key.
	 * 
	 * @return
	 */
	private RSAPublicKey getRSAPublicKey() {
		PublicKey publicKey = this.keyPair.getPublic();
		RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
		return rsaPublicKey;
	}

	/**
	 * Gives back the RSA private key.
	 * 
	 * @return
	 */
	public PrivateKey getPrivate() {
		return this.keyPair.getPrivate();
	}

	/**
	 * Sets the validity period of the MyCareNet session key.
	 * 
	 * @param notBefore
	 * @param notAfter
	 */
	public void setValidity(Date notBefore, Date notAfter) {
		this.notBefore = notBefore;
		this.notAfter = notAfter;
	}

	/**
	 * Checks whether this MyCareNet session key still operates within its
	 * validity period.
	 * 
	 * @return
	 */
	public boolean isValid() {
		if (null == this.notBefore) {
			LOG.debug("no notBefore");
			return false;
		}
		if (null == this.notAfter) {
			LOG.debug("no notAfter");
			return false;
		}
		Date now = new Date();
		if (now.before(this.notBefore)) {
			LOG.debug("session key not yet active");
			LOG.debug("now: " + now);
			LOG.debug("notBefore: " + this.notBefore);
			return false;
		}
		if (now.after(this.notAfter)) {
			LOG.debug("session key expired");
			return false;
		}
		return true;
	}

	public Date getNotBefore() {
		return this.notBefore;
	}

	public Date getNotAfter() {
		return this.notAfter;
	}

	public byte[] getEncodedPrivateKey() {
		return this.getPrivate().getEncoded();
	}

	public byte[] getEncodedPublicKey() {
		return this.getRSAPublicKey().getEncoded();
	}

	public X509Certificate getCertificate() {
		if (null == this.certificate) {
			generateCertificate();
		}
		return this.certificate;
	}

	private void generateCertificate() {
		X500Name name = new X500Name(this.name);
		BigInteger serial = BigInteger.valueOf(1);
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
				.getInstance(this.keyPair.getPublic().getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
				name, serial, this.notBefore, this.notAfter, name,
				publicKeyInfo);
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
				.find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
				.find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter;
		try {
			asymmetricKeyParameter = PrivateKeyFactory.createKey(this.keyPair
					.getPrivate().getEncoded());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		ContentSigner contentSigner;
		try {
			contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
					.build(asymmetricKeyParameter);
		} catch (OperatorCreationException e) {
			throw new RuntimeException(e);
		}
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder
				.build(contentSigner);

		byte[] encodedCertificate;
		try {
			encodedCertificate = x509CertificateHolder.getEncoded();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
		try {
			this.certificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(
							encodedCertificate));
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] getEncodedCertificate() {
		X509Certificate certificate = getCertificate();
		try {
			return certificate.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("certificate encoding error: "
					+ e.getMessage(), e);
		}
	}
}
