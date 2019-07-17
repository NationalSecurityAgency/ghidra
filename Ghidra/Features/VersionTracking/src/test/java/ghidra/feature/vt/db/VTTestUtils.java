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

//import generic.test.GenericTestCase;
import generic.test.AbstractGenericTest;
import ghidra.feature.vt.api.db.VTAssociationDB;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.impl.MarkupItemImpl;
import ghidra.feature.vt.api.impl.MarkupItemManagerImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markupitem.MarkupTypeTestStub;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.markuptype.VTMarkupTypeFactory;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class VTTestUtils {

	private static String[] randomTags = { "TAG1", "TAG2", "TAG3" };
	private static GenericAddressSpace space = new GenericAddressSpace("Test", 32,
		AddressSpace.TYPE_RAM, 3);

	private VTTestUtils() {
		// utility class
	}

	public static VTProgramCorrelator createProgramCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, Program destinationProgram) {
		return new DummyTestProgramCorrelator(serviceProvider, sourceProgram, destinationProgram);
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

	public static VTAssociationType getRandomType() {
		VTAssociationType[] values = VTAssociationType.values();
		return values[getRandomInt(0, values.length - 1)];
	}

	public static String getRandomString() {
		return "STR_" + getRandomInt();
	}

	public static int getRandomInt(int min, int max) {
		return min + (int) ((Math.random() * (max - min)));
	}

	public static int getRandomInt() {
		return getRandomInt(0, Integer.MAX_VALUE);
	}

	public static Address addr() {
		return addr(getRandomInt());
	}

	public static Address addr(String offset, Program p) {
		AddressFactory addressFactory = p.getAddressFactory();
		return addressFactory.getAddress(offset);
	}

	public static Address addr(long offset) {
		return space.getAddress(offset);
	}

	public static Address otherAddr(Address address) {
		Address newAddress = addr();
		while (newAddress.equals(address)) {
			newAddress = addr();
		}
		return newAddress;
	}

	/**
	 * Create a random match.
	 * @param session the match set manager to use when creating a random tag or 
	 * null if you don't want to create a random tag.
	 * @return the match
	 */
	public static VTMatchInfo createRandomMatch(VTSession session) {
		return createRandomMatch(addr(), addr(), session);
	}

	/**
	 * Create a random match
	 * @param association the association to use for the source and destination address.
	 * @param session the match set manager to use when creating a random tag or 
	 * null if you don't want to create a random tag.
	 * @return the match
	 */

	/**
	 * Create random match info between given source and destination addresses and in a given session.
	 * @param sourceAddress {@code Address}
	 * @param destinationAddress {@code Address}
	 * @param session {@code VTSession}
	 * @return VTMatchInfo with random lengths, scores, and associations type
	 */
	public static VTMatchInfo createRandomMatch(Address sourceAddress, Address destinationAddress,
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

	public static VTMarkupItem createRandomMarkupItemStub(VTMatch match) {
		return createRandomMarkupItemStub(match, match.getAssociation().getSourceAddress());
	}

	public static VTMarkupItem createRandomMarkupItemStub(VTMatch match, Address sourceAddress) {
		VTAssociationDB associationDB = (VTAssociationDB) match.getAssociation();
		VTMarkupType markupType = MarkupTypeTestStub.INSTANCE;

		VTMarkupItem markupItem = new MarkupItemImpl(associationDB, markupType, sourceAddress);

		Object markupItemManager = AbstractGenericTest.getInstanceField("markupManager", associationDB);
		if (!(markupItemManager instanceof MarkupItemManagerImplDummy)) {

			// Odd Code Alert: we don't want the MarkupItemManager actually looking for markup items
			//                 while we are testing, as it is slow.  Thus, we will swap out the real
			//                 implementation for a test dummy.
			MarkupItemManagerImplDummy dummy = new MarkupItemManagerImplDummy(associationDB);
			AbstractGenericTest.setInstanceField("markupManager", associationDB, dummy);
			markupItemManager = dummy;
		}
		MarkupItemManagerImplDummy dummy = (MarkupItemManagerImplDummy) markupItemManager;
		dummy.addMarkupItem(markupItem);

		return markupItem;
	}

	private static class MarkupItemManagerImplDummy extends MarkupItemManagerImpl {
		List<VTMarkupItem> injectedItems = new ArrayList<VTMarkupItem>();

		MarkupItemManagerImplDummy(VTAssociationDB associationDB) {
			super(associationDB);
		}

		public void addMarkupItem(VTMarkupItem markupItem) {
			injectedItems.add(markupItem);
		}

		@Override
		protected Collection<VTMarkupItem> getGeneratedMarkupItems(TaskMonitor monitor)
				throws CancelledException {
			return injectedItems;
		}
	}

	public static VTMatch createMatchSetWithOneMatch(VTSessionDB db) throws Exception {
		return createMatchSetWithOneMatch(db, addr(), addr());
	}

	public static VTMatch createMatchSetWithOneMatch(VTSessionDB db, Address sourceAddress,
			Address destinationAddress) throws Exception {
		int testTransactionID = 0;
		try {
			testTransactionID = db.startTransaction("Test Match Set Setup");
			VTMatchInfo info = createRandomMatch(sourceAddress, destinationAddress, db);
			VTMatchSet matchSet =
				db.createMatchSet(createProgramCorrelator(null, db.getSourceProgram(),
					db.getDestinationProgram()));
			return matchSet.addMatch(info);
		}
		finally {
			db.endTransaction(testTransactionID, true);
		}
	}

	public static VTMatch createMatchSetWithOneDataMatch(VTSessionDB db, Address sourceAddress,
			Address destinationAddress) throws Exception {
		int testTransactionID = 0;
		try {
			testTransactionID = db.startTransaction("Test Create Data Match Set");
			VTMatchInfo info = createRandomMatch(sourceAddress, destinationAddress, db);
			info.setAssociationType(VTAssociationType.DATA);
			VTMatchSet matchSet =
				db.createMatchSet(createProgramCorrelator(null, db.getSourceProgram(),
					db.getDestinationProgram()));
			return matchSet.addMatch(info);
		}
		finally {
			db.endTransaction(testTransactionID, true);
		}
	}

	public static VTMarkupType getRandomMarkupMigratorClass() {
		List<VTMarkupType> markupTypes = VTMarkupTypeFactory.getMarkupTypes();
		return markupTypes.get(getRandomInt(0, markupTypes.size() - 1));
	}

	public static String createRandomString() {
		int stringLength = getRandomInt(0, 20);
		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < stringLength; i++) {
			buffy.append((char) getRandomInt(65, 127));
		}
		return buffy.toString();
	}

	public static VTMarkupItemStatus getRandomMarkupStatus() {
		return VTMarkupItemStatus.values()[getRandomInt(1, VTMarkupItemStatus.values().length - 1)];
	}

	public static VTMarkupItemStatus getDifferentRandomMarkupStatus(VTMarkupItemStatus statusSeed) {
		VTMarkupItemStatus status =
			VTMarkupItemStatus.values()[getRandomInt(1, VTMarkupItemStatus.values().length - 1)];

		while (status == statusSeed) {
			status =
				VTMarkupItemStatus.values()[getRandomInt(1, VTMarkupItemStatus.values().length - 1)];
		}

		return status;
	}
}
