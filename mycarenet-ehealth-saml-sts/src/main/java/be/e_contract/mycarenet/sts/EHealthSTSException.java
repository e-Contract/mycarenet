/*
 * Java MyCareNet Project.
 * Copyright (C) 2018 e-Contract.be BVBA.
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

import org.w3c.dom.Element;

/**
 * Gets thrown in case the eHealth STS returned an error.
 * 
 * @author Frank Cornelis
 *
 */
public class EHealthSTSException extends Exception {

	private static final long serialVersionUID = 1L;

	private final Element statusElement;

	public EHealthSTSException(Element statusElement) {
		this.statusElement = statusElement;
	}

	public Element getStatusElement() {
		return this.statusElement;
	}
}
