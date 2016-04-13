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

package test.unit.be.e_contract.mycarenet.certra.cms;

import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;

import be.e_contract.mycarenet.certra.cms.CMSSigner;
import be.e_contract.mycarenet.certra.cms.revoke.ObjectFactory;
import be.e_contract.mycarenet.certra.cms.revoke.RevocableCertificatesDataRequest;

public class CMSSignerTest {

	@BeforeClass
	public static void beforeClass() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testSignRevocableCertificatesDataRequest() throws Exception {
		// setup
		ObjectFactory objectFactory = new ObjectFactory();
		RevocableCertificatesDataRequest request = objectFactory.createRevocableCertificatesDataRequest();
		request.setSSIN("12345678");

		KeyPair keyPair = generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		X509Certificate certificate = generateCertificate(keyPair, "CN=Test");

		CMSSigner cmsSigner = new CMSSigner(privateKey, Collections.singletonList(certificate));

		// operate
		byte[] result = cmsSigner.sign(request);

		// verify
		assertNotNull(result);
	}

	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		return keyPair;
	}

	public static X509Certificate generateCertificate(KeyPair keyPair, String distinguishedName) throws Exception {
		X500Name issuerX500Name = new X500Name(distinguishedName);
		X500Name subjectX500Name = new X500Name(distinguishedName);

		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

		SecureRandom secureRandom = new SecureRandom();
		byte[] serialValue = new byte[8];
		secureRandom.nextBytes(serialValue);
		BigInteger serial = new BigInteger(serialValue);

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerX500Name, serial,
				notBefore.toDate(), notAfter.toDate(), subjectX500Name, publicKeyInfo);

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
		ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);

		byte[] encodedCertificate = x509CertificateHolder.getEncoded();

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(encodedCertificate));
		return certificate;
	}
}
