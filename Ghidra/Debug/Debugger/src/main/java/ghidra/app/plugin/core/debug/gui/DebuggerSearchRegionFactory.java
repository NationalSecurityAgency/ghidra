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
package ghidra.app.plugin.core.debug.gui;

import java.util.List;

import ghidra.features.base.memsearch.bytesource.SearchRegion;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public enum DebuggerSearchRegionFactory {
	FULL_SPACE("All Addresses", """
			Searches all memory in the space, regardless of known validity.""") {

		@Override
		AddressSetView getAddresses(AddressSpace space, Program program) {
			AddressSet set = new AddressSet();
			if (space != null) {
				set.add(space.getMinAddress(), space.getMaxAddress());
				return set;
			}
			for (AddressSpace s : program.getAddressFactory().getAddressSpaces()) {
				set.add(s.getMinAddress(), s.getMaxAddress());
			}
			return set;
		}
	},
	VALID("Valid Addresses", """
			Searches listed memory regions in the space.""") {

		@Override
		AddressSetView getAddresses(AddressSpace space, Program program) {
			AddressSet set = new AddressSet();
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (space == null || space == block.getStart().getAddressSpace()) {
					set.add(block.getAddressRange());
				}
			}
			return set;
		}

		@Override
		boolean isDefault(AddressSpace space) {
			return space == null;
		}
	},
	WRITABLE("Writable Addresses", """
			Searches listed regions marked as writable in the space.""") {

		@Override
		AddressSetView getAddresses(AddressSpace space, Program program) {
			AddressSet set = new AddressSet();
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (block.isWrite() &&
					(space == null || space == block.getStart().getAddressSpace())) {
					set.add(block.getAddressRange());
				}
			}
			return set;
		}
	};

	public static final List<DebuggerSearchRegionFactory> ALL = List.of(values());

	record DebuggerSearchRegion(DebuggerSearchRegionFactory factory, AddressSpace spaces)
			implements SearchRegion {
		@Override
		public String getName() {
			return factory.getName(spaces);
		}

		@Override
		public String getDescription() {
			return factory.getDescription(spaces);
		}

		@Override
		public AddressSetView getAddresses(Program program) {
			return factory.getAddresses(spaces, program);
		}

		@Override
		public boolean isDefault() {
			return factory.isDefault(spaces);
		}
	}

	private final String namePrefix;
	private final String description;

	private DebuggerSearchRegionFactory(String namePrefix, String description) {
		this.namePrefix = namePrefix;
		this.description = description;
	}

	public SearchRegion createRegion(AddressSpace space) {
		return new DebuggerSearchRegion(this, space);
	}

	String getName(AddressSpace space) {
		if (space == null) {
			return namePrefix;
		}
		return "%s (%s)".formatted(namePrefix, space.getName());
	}

	String getDescription(AddressSpace spaces) {
		return description;
	}

	abstract AddressSetView getAddresses(AddressSpace space, Program program);

	boolean isDefault(AddressSpace space) {
		return false;
	}
}
