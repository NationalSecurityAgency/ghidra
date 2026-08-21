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
package ghidra.features.base.memsearch.bytesource;

import java.util.List;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

/**
 * An enum specifying the selectable regions within a {@link Program} that users can select for
 * searching memory. 
 */
public enum ProgramSearchRegion implements SearchRegion {
	LOADED("Loaded Blocks",
			"Searches all memory blocks that represent loaded program instructions and data") {

		@Override
		public boolean isDefault() {
			return true;
		}

		@Override
		public AddressSetView getAddresses(Program program) {
			Memory memory = program.getMemory();
			return memory.getLoadedAndInitializedAddressSet();
		}
	},
	OTHER("All Other Blocks", "Searches non-loaded initialized blocks") {

		@Override
		public boolean isDefault() {
			return false;
		}

		@Override
		public AddressSetView getAddresses(Program program) {
			Memory memory = program.getMemory();
			AddressSetView all = memory.getAllInitializedAddressSet();
			AddressSetView loaded = memory.getLoadedAndInitializedAddressSet();
			return all.subtract(loaded);
		}
	};

	public static final List<SearchRegion> ALL = List.of(values());

	private String name;
	private String description;

	ProgramSearchRegion(String name, String description) {
		this.name = name;
		this.description = description;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getDescription() {
		return description;
	}
}
