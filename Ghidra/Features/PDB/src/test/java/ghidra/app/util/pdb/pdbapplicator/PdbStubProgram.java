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
package ghidra.app.util.pdb.pdbapplicator;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.StubProgram;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

/**
 * Stub Program for some PDB tests
 */

public class PdbStubProgram extends StubProgram {

	private DomainFile domainFile;

	private AddressSpace space;
	private AddressFactory factory;
	private static long imageBaseVal = 0x400000L;
	private Address imageBase;
	private SymbolTable symbolTable;
	private Memory memory;
	private Listing listing;

	public PdbStubProgram(DomainFile domainFile) {
		this.domainFile = domainFile;
		space = new GenericAddressSpace("xx", 64, AddressSpace.TYPE_RAM, 0);
		factory = new DefaultAddressFactory(new AddressSpace[] { space });
		imageBase = factory.getAddress(space.getSpaceID(), imageBaseVal);
		symbolTable = new PdbStubSymbolTable();
		memory = new PdbStubMemory(imageBase);
		listing = new PdbStubListing();
	}

	@Override
	public DomainFile getDomainFile() {
		return domainFile;
	}

	@Override
	public Address getImageBase() {
		return imageBase;
	}

	@Override
	public SymbolTable getSymbolTable() {
		return symbolTable;
	}

	@Override
	public Memory getMemory() {
		return memory;
	}
//	@Override
//	public ProgramDataTypeManager getDataTypeManager() {
//		return dataTypeManager;
//	}
//

	@Override
	public AddressFactory getAddressFactory() {
		return factory;
	}

	@Override
	public Listing getListing() {
		return listing;
	}

	@Override
	public boolean hasExclusiveAccess() {
		return true;
	}

	private class PdbStubSymbolTable extends StubSymbolTable {
		@Override
		public SymbolIterator getAllSymbols(boolean includeDynamicSymbols) {
			return SymbolIterator.EMPTY_ITERATOR;
		}
//
//		@Override
//		public SymbolIterator getPrimarySymbolIterator(AddressSetView asv, boolean forward) {
//			return SymbolIterator.EMPTY_ITERATOR;
//		}
	}

	private class PdbStubMemory extends StubMemory {

		private static final int NUM_BLOCKS = 1000;
		private static final long BLOCK_SIZE = 1000000;
		private static final MemoryBlock[] blocks = new MemoryBlock[NUM_BLOCKS];

		PdbStubMemory(Address imageBase) {
			Address address = imageBase;
			for (int block = 0; block < NUM_BLOCKS; block++) {
				// We are pre-incrementing so that we do not get a "zero" address for our
				// processing
				address = address.add(BLOCK_SIZE);
				blocks[block] = new PdbMemoryBlock(address, BLOCK_SIZE);
			}
		}

		@Override
		public MemoryBlock[] getBlocks() {
			return blocks;
		}
	}

	private class PdbMemoryBlock extends MemoryBlockStub {

		private Address address;
		private long size;

		PdbMemoryBlock(Address address, long size) {
			this.address = address;
			this.size = size;
		}

		@Override
		public Address getStart() {
			return address;
		}

		@Override
		public long getSize() {
			return size;
		}
	}

	private class PdbStubListing extends StubListing {

		@Override
		public CodeUnit getCodeUnitContaining(Address addr) {
			return new PdbInstructionStub(addr);
		}

	}

	private class PdbInstructionStub extends InstructionStub {

		Address address;

		PdbInstructionStub(Address addr) {
			address = addr;
		}

		@Override
		public Address getAddress() {
			return address;
		}

	}

}
