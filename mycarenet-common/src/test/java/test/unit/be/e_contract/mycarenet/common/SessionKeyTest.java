/*
 * Java MyCareNet Project.
 * Copyright (C) 2012 Frank Cornelis.
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

package test.unit.be.e_contract.mycarenet.common;

import static org.junit.Assert.assertArrayEquals;

import java.util.Date;

import org.junit.Test;

import be.e_contract.mycarenet.common.SessionKey;

public class SessionKeyTest {

	@Test
	public void testSessionKeyLoading() {
		// setup
		Date notBefore = new Date();
		Date notAfter = new Date();
		SessionKey sessionKey = new SessionKey();
		byte[] encodedPrivateKey = sessionKey.getEncodedPrivateKey();
		byte[] encodedPublicKey = sessionKey.getEncodedPublicKey();
		sessionKey.setValidity(notBefore, notAfter);
		byte[] encodedCertificate = sessionKey.getEncodedCertificate();

		// operate
		SessionKey loadedSessionKey = new SessionKey(encodedPrivateKey,
				encodedPublicKey, encodedCertificate, notBefore, notAfter);

		// verify
		assertArrayEquals(encodedPrivateKey,
				loadedSessionKey.getEncodedPrivateKey());
		assertArrayEquals(encodedPublicKey,
				loadedSessionKey.getEncodedPublicKey());
		assertArrayEquals(encodedCertificate,
				loadedSessionKey.getEncodedCertificate());
	}

}
