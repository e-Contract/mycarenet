/*
 * Java MyCareNet Project.
 * Copyright (C) 2012-2013 e-Contract.be BVBA.
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

package test.integ.be.e_contract.mycarenet;

import java.io.IOException;
import java.util.Properties;

import be.e_contract.mycarenet.async.PackageLicenseKey;

public class Config {

	private final PackageLicenseKey packageLicenseKey;

	private final String eHealthPKCS12Path;

	private final String eHealthPKCS12Password;

	public Config() throws IOException {
		Properties properties = new Properties();
		properties.load(Config.class
				.getResourceAsStream("/mycarenet-tests.properties"));
		String licenseKeyUsername = properties
				.getProperty("licensekey.username");
		String licenseKeyPassword = properties
				.getProperty("licensekey.password");
		this.packageLicenseKey = new PackageLicenseKey(licenseKeyUsername,
				licenseKeyPassword);

		this.eHealthPKCS12Path = properties.getProperty("ehealth.p12.path");
		this.eHealthPKCS12Password = properties
				.getProperty("ehealth.p12.password");
	}

	public PackageLicenseKey getPackageLicenseKey() {
		return this.packageLicenseKey;
	}

	public String getEHealthPKCS12Path() {
		return this.eHealthPKCS12Path;
	}

	public String getEHealthPKCS12Password() {
		return this.eHealthPKCS12Password;
	}
}
