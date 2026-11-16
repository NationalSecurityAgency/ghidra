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
package ghidra.app.plugin.core.debug.gui.slice;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;

/**
 * Represents a single row in the path examination table.
 */
public class PathRow {
	private final long snap;
	private final String location;
	private final Address address;
	private final CodeUnit codeUnit;

	private boolean checked;

	public PathRow(long snap, String location, Address address, CodeUnit codeUnit) {
		this.snap = snap;
		this.location = location;
		this.address = address;
		this.codeUnit = codeUnit;
	}

	public long getSnap() {
		return snap;
	}

	public String getLocation() {
		return location;
	}

	public Address getAddress() {
		return address;
	}

	public CodeUnit getCodeUnit() {
		return codeUnit;
	}

	public String getAddressString() {
		return address == null ? "" : address.toString();
	}

	public boolean isChecked() {
		return checked;
	}

	public void setChecked(boolean checked) {
		this.checked = checked;
	}
}
