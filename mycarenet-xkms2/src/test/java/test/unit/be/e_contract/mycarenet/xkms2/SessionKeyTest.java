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

package test.unit.be.e_contract.mycarenet.xkms2;

import static org.junit.Assert.*;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.e_contract.mycarenet.common.SessionKey;

public class SessionKeyTest {

	private static final Log LOG = LogFactory.getLog(SessionKeyTest.class);

	@Test
	public void testSelfSignedCertificate() {
		SessionKey sessionKey = new SessionKey();
		Date notBefore = new Date();
		Date notAfter = new Date();
		sessionKey.setValidity(notBefore, notAfter);
		X509Certificate certificate = sessionKey.getCertificate();
		assertNotNull(certificate);
		LOG.debug("self-signed certificate: " + certificate);
	}

}
