/*
 * Java MyCareNet Project.
 * Copyright (C) 2012-2022 e-Contract.be BV.
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

package test.unit.be.e_contract.mycarenet.xkms2;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.mycarenet.common.SessionKey;

public class SessionKeyTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(SessionKeyTest.class);

	@Test
	public void testSelfSignedCertificate() {
		SessionKey sessionKey = new SessionKey();
		Date notBefore = new Date();
		Date notAfter = new Date();
		sessionKey.setValidity(notBefore, notAfter);
		X509Certificate certificate = sessionKey.getCertificate();
		assertNotNull(certificate);
		LOGGER.debug("self-signed certificate: {}", certificate);
	}
}
