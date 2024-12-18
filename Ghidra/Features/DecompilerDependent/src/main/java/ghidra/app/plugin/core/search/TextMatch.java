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
package ghidra.app.plugin.core.search;

import generic.json.Json;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;

/**
 * A simple class that represents text found in Decompiler output.
 */
public class TextMatch {

	private Function function;
	private AddressSet addresses;
	private LocationReferenceContext context;
	private int lineNumber;

	private String searchText;
	private boolean isMultiLine;

	TextMatch(Function function, AddressSet addresses, int lineNumber, String searchText,
			LocationReferenceContext context, boolean isMultiLine) {
		this.function = function;
		this.addresses = addresses;
		this.lineNumber = lineNumber;
		this.searchText = searchText;
		this.context = context;
		this.isMultiLine = isMultiLine;
	}

	public Function getFunction() {
		return function;
	}

	public LocationReferenceContext getContext() {
		return context;
	}

	public int getLineNumber() {
		return lineNumber;
	}

	public Address getAddress() {
		if (addresses.isEmpty()) {
			return function.getEntryPoint();
		}

		return addresses.getFirstRange().getMinAddress();
	}

	public boolean isMultiLine() {
		return isMultiLine;
	}

	public String getSearchText() {
		return searchText;
	}

	@Override
	public String toString() {
		return Json.toString(this, "function", "context", "searchText");
	}
}
