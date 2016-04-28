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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;

public class CertRASession {

	private final PrivateKey privateKey;

	private final PublicKey publicKey;

	public CertRASession() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		RSAKeyGenParameterSpec params = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);

		SecureRandom secureRandom = new SecureRandom();
		secureRandom.setSeed(System.currentTimeMillis());

		keyPairGenerator.initialize(params, secureRandom);
		KeyPair keyPair = keyPairGenerator.genKeyPair();

		this.privateKey = keyPair.getPrivate();
		this.publicKey = keyPair.getPublic();
	}
}
