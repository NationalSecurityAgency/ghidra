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
package ghidra.app.util.bin.format.dwarf.external.gui;


import ghidra.app.util.bin.format.dwarf.external.*;

/**
 * Represents a row in a ExternalDebugInfoProviderTableModel
 */
class ExternalDebugInfoProviderTableRow {

	private DebugInfoProvider item;
	private DebugInfoProviderStatus status = DebugInfoProviderStatus.UNKNOWN;

	ExternalDebugInfoProviderTableRow(DebugInfoProvider item) {
		this.item = item;
	}

	DebugInfoProvider getItem() {
		return item;
	}

	void setItem(DebugInfoProvider newItem) {
		this.item = newItem;
	}

	DebugInfoProviderStatus getStatus() {
		return status;
	}

	void setStatus(DebugInfoProviderStatus status) {
		this.status = status;
	}

	boolean isEnabled() {
		return !(item instanceof DisabledDebugInfoProvider);
	}

	void setEnabled(boolean enabled) {
		if (isEnabled() == enabled) {
			return;
		}
		status = DebugInfoProviderStatus.UNKNOWN;
		if (enabled) {
			DisabledDebugInfoProvider dss = (DisabledDebugInfoProvider) item;
			item = dss.getDelegate();
		}
		else {
			item = new DisabledDebugInfoProvider(item);
		}
	}

	@Override
	public String toString() {
		return String.format("SearchLocationsTableRow: [ status: %s, item: %s]", status.toString(),
			item.toString());
	}

}
