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
package ghidra.feature.vt.db;

import java.io.IOException;

import org.junit.After;
import org.junit.Before;

import generic.test.AbstractGenericTest;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.TestDummyDomainFile;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.StubFunctionManager;
import ghidra.program.model.StubProgram;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.StubMemory;
import ghidra.program.model.symbol.*;

public class VTBaseTestCase extends AbstractGenericTest {

	private DomainFile sourceDomainFile = new TestDummyDomainFile(null, "SourceDomainFile") {
		@Override
		public String getFileID() {
			return "Source Program " + testID;
		}
	};
	private DomainFile destinationDomainFile =
		new TestDummyDomainFile(null, "DestinationDomainFile") {
			@Override
			public String getFileID() {
				return "Destination Program " + testID;
			}
		};

	private Program sourceProgram = new VTStubProgram(sourceDomainFile);
	private Program destinationProgram = new VTStubProgram(destinationDomainFile);
	private FunctionManager functionManager = new VTSTubFunctionManager();
	private Listing listing = new VTStubListing();
	private SymbolTable symbolTable = new VTStubSymbolTable();
	private Memory memory = new VTStubMemory();

	private AddressMap addressMap = new AddressMapTestDummy();

	private static String[] randomTags = { "TAG1", "TAG2", "TAG3" };
	private static GenericAddressSpace space =
		new GenericAddressSpace("Test", 32, AddressSpace.TYPE_RAM, 3);

	protected VTSessionDB db;
	private int transactionID;
	private static int testID = 0;

	@Before
	public void setUp() throws Exception {
		testID++;
		db = createVTSession();
		transactionID = db.startTransaction("Test");
	}

	@After
	public void tearDown() throws Exception {
		db.endTransaction(transactionID, false);
		db.release(VTTestUtils.class);
	}

	public VTSessionDB createVTSession() throws IOException {
		return VTSessionDB.createVTSession("Test DB", sourceProgram, destinationProgram,
			VTTestUtils.class);
	}

	public static int getRandomInt() {
		return getRandomInt(0, Integer.MAX_VALUE);
	}

	public Address addr() {
		return addr(getRandomInt());
	}

	public Address addr(long offset) {
		return space.getAddress(offset);
	}

	/**
	 * Create a random match.
	 * @param session the match set manager to use when creating a random tag or
	 * null if you don't want to create a random tag.
	 * @return the match
	 */
	public VTMatchInfo createRandomMatch(VTSession session) {
		return createRandomMatch(addr(), addr(), session);
	}

	/**
	 * Create a random match
	 * @param sourceAddress the source address
	 * @param destinationAddress the destination address
	 * @param session the match set manager to use when creating a random tag or
	 * null if you don't want to create a random tag.
	 * @return the match
	 */
	public VTMatchInfo createRandomMatch(Address sourceAddress, Address destinationAddress,
			VTSession session) {
		VTMatchInfo info = new VTMatchInfo(null);
		info.setSourceAddress(sourceAddress);
		info.setDestinationAddress(destinationAddress);
		info.setDestinationLength(getRandomInt());
		info.setSourceLength(getRandomInt());
		info.setSimilarityScore(new VTScore(getRandomInt()));
		info.setConfidenceScore(new VTScore(getRandomInt()));
		info.setAssociationType(getRandomType());
		// If we have a session then randomly create a tag for this match.
		if (session != null) {
			info.setTag(getRandomTag(session));
		}
		return info;
	}

	public static VTAssociationType getRandomType() {
		VTAssociationType[] values = VTAssociationType.values();
		return values[getRandomInt(0, values.length - 1)];
	}

	/**
	 * Randomly creates a match tag in the tag table for the specified match set manager.
	 * @param session the match set manager.
	 * @return the match tag.
	 */
	public static VTMatchTag getRandomTag(VTSession session) {
		int randomInt = getRandomInt(0, randomTags.length - 1);
		String name = randomTags[randomInt];
		return session.createMatchTag(name);
	}

//=================================================================================================
// Inner Classes
//=================================================================================================

	private class VTStubMemory extends StubMemory {
		@Override
		public AddressRangeIterator getAddressRanges() {
			return new EmptyAddressRangeIterator();
		}
	}

	private class VTStubSymbolTable extends StubSymbolTable {
		@Override
		public SymbolIterator getPrimarySymbolIterator(AddressSetView asv, boolean forward) {
			return SymbolIterator.EMPTY_ITERATOR;
		}
	}

	private class VTStubListing extends StubListing {
		@Override
		public CodeUnit getCodeUnitAt(Address addr) {
			return null;
		}

		@Override
		public AddressIterator getCommentAddressIterator(int commentType, AddressSetView addrSet,
				boolean forward) {
			return new EmptyAddressIterator();
		}
	}

	private class VTSTubFunctionManager extends StubFunctionManager {
		@Override
		public Function getFunctionContaining(Address addr) {
			return null;
		}

		@Override
		public Function getFunctionAt(Address entryPoint) {
			return null;
		}
	}

	private class VTStubProgram extends StubProgram {

		private DomainFile domainFile;

		VTStubProgram(DomainFile domainFile) {
			this.domainFile = domainFile;
		}

		@Override
		public DomainFile getDomainFile() {
			return domainFile;
		}

		@Override
		public long getUniqueProgramID() {
			return testID;
		}

		@Override
		public boolean addConsumer(Object consumer) {
			return true;
		}

		@Override
		public void release(Object consumer) {
			// stub
		}

		@Override
		public Memory getMemory() {
			return memory;
		}

		@Override
		public AddressMap getAddressMap() {
			return addressMap;
		}

		@Override
		public FunctionManager getFunctionManager() {
			return functionManager;
		}

		@Override
		public Listing getListing() {
			return listing;
		}

		@Override
		public AddressFactory getAddressFactory() {
			return null;
		}

		@Override
		public SymbolTable getSymbolTable() {
			return symbolTable;
		}

		@Override
		public long getModificationNumber() {
			return 0;
		}
	}
}
