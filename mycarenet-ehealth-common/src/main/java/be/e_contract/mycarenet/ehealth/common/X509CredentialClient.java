/*
 * Java MyCareNet Project.
 * Copyright (C) 2023 e-Contract.be BV.
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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Interface for web service clients that use X509 based credentials.
 *
 * @author Frank Cornelis
 */
public interface X509CredentialClient {

	/**
	 * Sets the credentials to be used by the web service client.
	 *
	 * @param privateKey
	 * @param certificate
	 */
	void setCredentials(PrivateKey privateKey, X509Certificate certificate);
}
