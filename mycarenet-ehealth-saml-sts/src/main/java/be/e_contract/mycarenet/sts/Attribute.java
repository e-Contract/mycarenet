/*
 * Java MyCareNet Project.
 * Copyright (C) 2013 e-Contract.be BVBA.
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

package be.e_contract.mycarenet.sts;

public class Attribute {

	private final String namespace;

	private final String name;

	private final String value;

	private final boolean injectNRNValue;

	public Attribute(String namespace, String name, String value) {
		this.namespace = namespace;
		this.name = name;
		this.value = value;
		this.injectNRNValue = false;
	}

	/**
	 * Constructor for attribute. Because this constructor has no value, the STS
	 * client will inject the national registration number as value.
	 * 
	 * @param namespace
	 * @param name
	 */
	public Attribute(String namespace, String name) {
		this.namespace = namespace;
		this.name = name;
		this.value = null;
		this.injectNRNValue = true;
	}

	public String getNamespace() {
		return this.namespace;
	}

	public String getName() {
		return this.name;
	}

	public String getValue() {
		return this.value;
	}

	public boolean isInjectNRNValue() {
		return this.injectNRNValue;
	}
}
