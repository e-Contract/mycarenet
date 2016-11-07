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

package be.e_contract.mycarenet.certra;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class CertRASession {

	private final PrivateKey privateKey;

	private final PublicKey publicKey;

	private final String emailPrivate;

	private final String phonePrivate;

	public CertRASession(String emailPrivate, String phonePrivate) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		RSAKeyGenParameterSpec params = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);

		SecureRandom secureRandom = new SecureRandom();
		secureRandom.setSeed(System.currentTimeMillis());

		keyPairGenerator.initialize(params, secureRandom);
		KeyPair keyPair = keyPairGenerator.genKeyPair();

		this.privateKey = keyPair.getPrivate();
		this.publicKey = keyPair.getPublic();

		this.emailPrivate = emailPrivate;
		this.phonePrivate = phonePrivate;
	}

	public byte[] generateCSR(X500Name name) throws OperatorCreationException, IOException {
		PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(name, this.publicKey);
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer = csBuilder.build(this.privateKey);
		PKCS10CertificationRequest csr = csrBuilder.build(signer);
		return csr.getEncoded();
	}
}
