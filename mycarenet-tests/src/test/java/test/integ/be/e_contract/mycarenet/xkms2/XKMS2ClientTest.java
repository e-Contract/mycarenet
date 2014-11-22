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

package test.integ.be.e_contract.mycarenet.xkms2;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.junit.Test;

import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.xkms2.XKMS2Client;
import be.fedict.commons.eid.jca.BeIDProvider;

public class XKMS2ClientTest {

	@Test
	public void testRegisterRevokeSessionKey() throws Exception {
		// setup
		String xkms2Location = "https://pilot.mycarenet.be/mycarenet-ws/care-provider/xkms2";
		XKMS2Client xkms2Client = new XKMS2Client(xkms2Location);
		SessionKey sessionKey = new SessionKey();

		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey(
				"Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore
				.getCertificate("Authentication");

		// operate
		xkms2Client.registerSessionKey(sessionKey, authnPrivateKey,
				authnCertificate);

		// verify
		assertTrue(sessionKey.isValid());

		// operate
		xkms2Client.revokeSessionKey(sessionKey, authnPrivateKey,
				authnCertificate);

		// verify
		assertFalse(sessionKey.isValid());
	}
}
