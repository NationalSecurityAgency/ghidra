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
package ghidra.app.plugin.core.debug.gui.modules;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.trace.model.modules.TraceModule;
import ghidra.util.database.UndoableTransaction;

public class ModuleRow {
	private final TraceModule module;

	public ModuleRow(TraceModule module) {
		this.module = module;
	}

	public TraceModule getModule() {
		return module;
	}

	public void setName(String name) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(module.getTrace(), "Renamed module", true)) {
			module.setName(name);
		}
	}

	public String getShortName() {
		String name = module.getName();
		int sep = name.lastIndexOf('\\');
		if (sep > 0 && sep < name.length()) {
			name = name.substring(sep + 1);
		}
		sep = name.lastIndexOf('/');
		if (sep > 0 && sep < name.length()) {
			name = name.substring(sep + 1);
		}
		return name;
	}

	public String getName() {
		return module.getName();
	}

	public Address getBase() {
		return module.getBase();
	}

	public Address getMaxAddress() {
		return module.getMaxAddress();
	}

	public long getLoadedSnap() {
		return module.getLoadedSnap();
	}

	public Long getUnloadedSnap() {
		long snap = module.getUnloadedSnap();
		return snap == Long.MAX_VALUE ? null : snap;
	}

	public Range<Long> getLifespan() {
		return module.getLifespan();
	}

	public long getLength() {
		return module.getLength();
	}
}
