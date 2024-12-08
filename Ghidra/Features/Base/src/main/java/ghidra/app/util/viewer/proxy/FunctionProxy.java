/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Created on Aug 11, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package ghidra.app.util.viewer.proxy;

import java.util.ConcurrentModificationException;

import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

/**
 * Stores information about a function in a program such that the function can 
 * be retrieved when needed.  The locationAddr and functionAddr may differ when the
 * function object has been inferred via a reference at the locationAddr.
 */
public class FunctionProxy extends ProxyObj<Function> {
	private Program program;
	private Function function;
	private Address functionAddr;
	private Address locationAddr;

	/**
	 * Construct a proxy for a function
	 * @param model listing model
	 * @param program the program containing the function
	 * @param locationAddr the listing address at which the function exists or was inferred via reference
	 * @param function the function to proxy
	 */
	public FunctionProxy(ListingModel model, Program program, Address locationAddr,
			Function function) {
		super(model);
		this.program = program;
		this.function = function;
		this.locationAddr = locationAddr;
		this.functionAddr = function.getEntryPoint();
	}

	public Address getLocationAddress() {
		return locationAddr;
	}

	public Address getFunctionAddress() {
		return functionAddr;
	}

	@Override
	public Function getObject() {
		if (function != null) {
			try {
				function.getEntryPoint();
				return function;
			}
			catch (ConcurrentModificationException e) {
			}
		}
		function = null;

		Listing listing = program.getListing();

		if (!locationAddr.equals(functionAddr)) {
			// ensure that inferred function reference is valid
			if (listing.getFunctionAt(locationAddr) != null) {
				return null;
			}
			CodeUnit cu = listing.getCodeUnitAt(locationAddr);
			if (!(cu instanceof Data)) {
				return null;
			}
			Data data = (Data) cu;
			if (!(data.getDataType() instanceof Pointer)) {
				return null;
			}
			Reference ref = data.getPrimaryReference(0);
			if (ref == null || !ref.getToAddress().equals(functionAddr)) {
				return null;
			}
		}

		function = listing.getFunctionAt(functionAddr);
		return function;
	}

	@Override
	public boolean contains(Address a) {
		Function f = getObject();
		if (f == null) {
			return false;
		}
		return f.getBody().contains(a);
	}
}
