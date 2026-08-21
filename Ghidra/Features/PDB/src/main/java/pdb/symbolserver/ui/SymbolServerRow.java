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
package pdb.symbolserver.ui;

import static pdb.symbolserver.ui.SymbolServerRow.LocationStatus.*;

import ghidra.util.task.TaskMonitor;
import pdb.symbolserver.DisabledSymbolServer;
import pdb.symbolserver.SymbolServer;
import pdb.symbolserver.SymbolServer.MutableTrust;

/**
 * Represents a row in the {@link SymbolServerTableModel}
 */
class SymbolServerRow {

	public enum LocationStatus {
		UNKNOWN, VALID, INVALID
	}

	private SymbolServer symbolServer;
	private LocationStatus status = LocationStatus.UNKNOWN;

	SymbolServerRow(SymbolServer symbolServer) {
		this.symbolServer = symbolServer;
	}

	SymbolServer getSymbolServer() {
		return symbolServer;
	}

	void setSymbolServer(SymbolServer symbolServer) {
		this.symbolServer = symbolServer;
	}

	boolean isEnabled() {
		return !(symbolServer instanceof DisabledSymbolServer);
	}

	void setEnabled(boolean enabled) {
		if (isEnabled() == enabled) {
			return;
		}
		if (enabled) {
			DisabledSymbolServer dss = (DisabledSymbolServer) symbolServer;
			symbolServer = dss.getSymbolServer();
		}
		else {
			symbolServer = new DisabledSymbolServer(symbolServer);
		}
	}

	boolean isTrusted() {
		return symbolServer.isTrusted();
	}

	void setTrusted(boolean isTrusted) {
		if (symbolServer instanceof MutableTrust sswt) {
			sswt.setTrusted(isTrusted);
		}
	}

	LocationStatus getStatus() {
		return status;
	}

	void setStatus(LocationStatus status) {
		this.status = status;
	}

	void updateStatus(TaskMonitor monitor) {
		if (!(symbolServer instanceof SymbolServer.StatusRequiresContext)) {
			this.status = symbolServer.isValid(monitor) ? VALID : INVALID;
		}
	}

	@Override
	public String toString() {
		return String.format("SymbolServerRow: [ status: %s, server: %s]", status.toString(),
			symbolServer.toString());
	}

}
