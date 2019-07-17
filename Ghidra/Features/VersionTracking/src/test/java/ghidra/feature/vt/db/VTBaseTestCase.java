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
import java.util.ArrayList;

import org.junit.After;
import org.junit.Before;

import generic.test.AbstractGenericTest;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import mockit.*;

public class VTBaseTestCase extends AbstractGenericTest {
	@Injectable
	Program sourceProgram, destinationProgram;
	@Mocked
	FunctionManager functionManager;
	@Mocked
	Listing listing;
	@Mocked
	SymbolTable symbolTable;
	@Injectable
	DomainFile sourceDomainFile, destinationDomainFile;
	@Mocked
	Memory memory;
	AddressMap addressMap = new AddressMapTestDummy();
	private static String[] randomTags = { "TAG1", "TAG2", "TAG3" };
	private static GenericAddressSpace space =
		new GenericAddressSpace("Test", 32, AddressSpace.TYPE_RAM, 3);

	protected VTSessionDB db;
	private int transactionID;
	private static int testID = 0;

	@Before
	public void setUp() throws Exception {
		testID++;
		setupCommonExpectations();
		setupSourceProgramExpectations();
		setupDestinationProgramExpectations();
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

	private void setupCommonExpectations() {
		new Expectations() {
			{
				functionManager.getFunctionContaining((Address) any);
				minTimes = 0;
				result = null;

				functionManager.getFunctionAt((Address) any);
				minTimes = 0;
				result = null;
			}
		};
		new Expectations() {
			{
				listing.getCodeUnitAt((Address) any);
				minTimes = 0;
				result = null;

				listing.getCommentAddressIterator(anyInt, null, true);
				minTimes = 0;
				result = new EmptyAddressIterator();
			}
		};

		new Expectations() {
			{
				symbolTable.getPrimarySymbolIterator((AddressSetView) any, true);
				minTimes = 0;
				result = new SymbolIteratorAdapter(new ArrayList<Symbol>().iterator());
			}
		};

	}

	private void setupDestinationProgramExpectations() {
		new Expectations() {
			{
				destinationDomainFile.getFileID();
				result = "Destination Program " + testID;
				destinationProgram.getDomainFile();
				result = destinationDomainFile;
			}
		};
		setupProgramExpectations(destinationProgram);
	}

	private void setupSourceProgramExpectations() {
		new Expectations() {
			{
				sourceDomainFile.getFileID();
				result = "Source Program " + testID;
				sourceProgram.getDomainFile();
				result = sourceDomainFile;
			}
		};
		setupProgramExpectations(sourceProgram);
	}

	private void setupProgramExpectations(final Program program) {
		new Expectations() {
			{
				program.addConsumer(any);
				minTimes = 0;
				program.release(any);
				minTimes = 0;
				program.getUniqueProgramID();
				minTimes = 0;
				result = testID;

				program.getMemory();
				minTimes = 0;
				result = memory;

				program.getAddressMap();
				minTimes = 0;
				result = addressMap;

				program.getFunctionManager();
				minTimes = 0;
				result = functionManager;

				program.getListing();
				minTimes = 0;
				result = listing;

				program.getAddressFactory();
				minTimes = 0;
				result = null;

				program.getSymbolTable();
				minTimes = 0;
				result = symbolTable;

				program.getModificationNumber();
				minTimes = 0;
				result = 0;
			}
		};

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
	 * @param association the association to use for the source and destination address.
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
}
