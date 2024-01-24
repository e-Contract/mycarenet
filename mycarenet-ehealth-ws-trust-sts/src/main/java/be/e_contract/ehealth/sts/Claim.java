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
package be.e_contract.ehealth.sts;

public class Claim {

	private final String name;

	private final String value;

	public Claim(String name, String value) {
		this.name = name;
		this.value = value;
	}

	public Claim(String name) {
		this(name, null);
	}

	public String getName() {
		return this.name;
	}

	public String getValue() {
		return this.value;
	}
}
