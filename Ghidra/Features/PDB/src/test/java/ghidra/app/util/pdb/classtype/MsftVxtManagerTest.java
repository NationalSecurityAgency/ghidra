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
package ghidra.app.util.pdb.classtype;

import static org.junit.Assert.*;

import java.util.*;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.checksums.MyTestMemory;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.SymbolPathParser;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Unit tests for the {@link MsftVxtManager}.
 * <p>
 * See {@link MsftVxtManager} for a description of what tests need to work
 */
public class MsftVxtManagerTest extends AbstractGenericTest {

	private static MessageLog log = new MessageLog();
	private static TaskMonitor monitor = TaskMonitor.DUMMY;

	private static DataTypeManager dtm32;
	private static DataTypeManager dtm64;
	// Didn't intend to modify this class to need these, but need them while modifying PdbVxtManager
	// to use them
	private static ClassTypeManager ctm32;
	private static ClassTypeManager ctm64;

	private ClassID a1Id = new ProgramClassID(CategoryPath.ROOT, sp("A1NS::A1"));
	private ClassID a2Id = new ProgramClassID(CategoryPath.ROOT, sp("A2NS::A2"));
	private ClassID aId = new ProgramClassID(CategoryPath.ROOT, sp("ANS::A"));
	private ClassID b1Id = new ProgramClassID(CategoryPath.ROOT, sp("B1NS::B1"));
	private ClassID b2Id = new ProgramClassID(CategoryPath.ROOT, sp("B2NS::B2"));
	private ClassID bId = new ProgramClassID(CategoryPath.ROOT, sp("BNS::B"));
	private ClassID cId = new ProgramClassID(CategoryPath.ROOT, sp("CNS::C"));
	private ClassID dId = new ProgramClassID(CategoryPath.ROOT, sp("DNS::D"));
	private ClassID eId = new ProgramClassID(CategoryPath.ROOT, sp("ENS::E"));
	private ClassID fId = new ProgramClassID(CategoryPath.ROOT, sp("FNS::F"));
	private ClassID gId = new ProgramClassID(CategoryPath.ROOT, sp("GNS::G"));
	private ClassID hId = new ProgramClassID(CategoryPath.ROOT, sp("HNS::H"));
	private ClassID iId = new ProgramClassID(CategoryPath.ROOT, sp("INS::I"));
	private ClassID jId = new ProgramClassID(CategoryPath.ROOT, sp("JNS::J"));
	private ClassID kId = new ProgramClassID(CategoryPath.ROOT, sp("KNS::K"));
	private ClassID lId = new ProgramClassID(CategoryPath.ROOT, sp("LNS::L"));
	private ClassID mId = new ProgramClassID(CategoryPath.ROOT, sp("MNS::M"));

	private static Memory memory32;
	private static Memory memory64;

	private static List<String> vbtSymbols = new ArrayList<>();
	private static List<String> vftSymbols = new ArrayList<>();
	private static List<Address> vxtAddresses32;
	private static List<Address> vxtAddresses64;

	private static Map<String, Address> addressByVxtMangledName32;
	private static Map<String, Address> addressByVxtMangledName64;

//	private static PointerDataType vftptr32;
//	private static PointerDataType vftptr64;
//	private static PointerDataType vbtptr32;
//	private static PointerDataType vbtptr64;

	private static MsftVxtManager mVxtManager32;
	private static MsftVxtManager mVxtManager64;

	static {
		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl();
		bitFieldPacking.setUseMSConvention(true);

		// DataOrganization based on x86win.cspec
		// The DataOrganizationImpl currently has defaults of a 32-bit windows cspec, but could
		// change in the future.
		DataOrganizationImpl dataOrg32 = DataOrganizationImpl.getDefaultOrganization(null);

		dtm32 = new TestDummyDataTypeManager() {
			HashMap<String, DataType> dataTypeMap = new HashMap<>();

			@Override
			public DataOrganization getDataOrganization() {
				return dataOrg32;
			}

			@Override
			public DataType addDataType(DataType dataType, DataTypeConflictHandler handler) {
				// handler ignored - tests should not induce conflicts
				String pathname = dataType.getPathName();
				DataType myDt = dataTypeMap.get(pathname);
				if (myDt != null) {
					return myDt;
				}
				DataType dt = dataType.clone(this);
				dataTypeMap.put(pathname, dt);
				return dt;
			}

			@Override
			public DataType findDataType(String dataTypePath) {
				return dataTypeMap.get(dataTypePath);
			}

			@Override
			public DataType getDataType(CategoryPath path, String name) {
				return super.getDataType(new DataTypePath(path, name).getPath());
			}

			@Override
			public DataType getDataType(String dataTypePath) {
				return dataTypeMap.get(dataTypePath);
			}
		};

		// DataOrganization based on x86-64-win.cspec
		DataOrganizationImpl dataOrg64 = DataOrganizationImpl.getDefaultOrganization(null);
		DataOrganizationTestUtils.initDataOrganizationWindows64BitX86(dataOrg64);

		dtm64 = new TestDummyDataTypeManager() {
			HashMap<String, DataType> dataTypeMap = new HashMap<>();

			@Override
			public DataOrganization getDataOrganization() {
				return dataOrg64;
			}

			@Override
			public DataType addDataType(DataType dataType, DataTypeConflictHandler handler) {
				// handler ignored - tests should not induce conflicts
				String pathname = dataType.getPathName();
				DataType myDt = dataTypeMap.get(pathname);
				if (myDt != null) {
					return myDt;
				}
				DataType dt = dataType.clone(this);
				dataTypeMap.put(pathname, dt);
				return dt;
			}

			@Override
			public DataType findDataType(String dataTypePath) {
				return dataTypeMap.get(dataTypePath);
			}

			@Override
			public DataType getDataType(CategoryPath path, String name) {
				return super.getDataType(new DataTypePath(path, name).getPath());
			}

			@Override
			public DataType getDataType(String dataTypePath) {
				return dataTypeMap.get(dataTypePath);
			}
		};

		// Didn't intend to modify this class to need these, but need them while modifying
		//  PdbVxtManager to use them
		ctm32 = new ClassTypeManager(dtm32);
		ctm64 = new ClassTypeManager(dtm64);
//		vftptr32 = new PointerDataType(new PointerDataType(dtm32));
//		vftptr64 = new PointerDataType(new PointerDataType(dtm64));
//		vbtptr32 = new PointerDataType(new IntegerDataType(dtm32));
//		vbtptr64 = new PointerDataType(new IntegerDataType(dtm64));

		createVxTables();

		mVxtManager32 = new MsftVxtManager(ctm32, memory32);
		mVxtManager64 = new MsftVxtManager(ctm64, memory64);

		try {
			mVxtManager32.createVirtualTables(CategoryPath.ROOT, addressByVxtMangledName32, log,
				monitor);
			mVxtManager64.createVirtualTables(CategoryPath.ROOT, addressByVxtMangledName64, log,
				monitor);
		}
		catch (CancelledException e) {
			// do nothing
		}

	}

	//==============================================================================================
	private static SymbolPath sp(String s) {
		return new SymbolPath(SymbolPathParser.parse(s));
	}

	//==============================================================================================

	private static void addBytesForIntegers(int[] ints, byte[] bytes, int startOffset) {
		int maxOffset = startOffset + 4 * ints.length;
		int index = 0;
		for (int offset = startOffset; offset < maxOffset; offset += 4) {
			LittleEndianDataConverter.INSTANCE.getBytes(ints[index++], bytes, offset);
		}
	}

	static class MemoryPreparer {
		private int nextOffset = 0;
		private List<int[]> intArrays = new ArrayList<>();
		private List<Integer> offsets = new ArrayList<>();
		private List<Address> addresses = new ArrayList<>();
		private MyTestMemory memory = null;
		private int mockAddressCounter = 0;

		void addAddresses(int numAddresses, boolean is64bit) {
			int[] integers;
			if (is64bit) {
				integers = new int[numAddresses * 2];
				for (int i = 0; i < numAddresses; i++) {
					integers[i * 2] = mockAddressCounter;
					integers[i * 2 + 1] = 0;
				}
			}
			else {
				integers = new int[numAddresses * 2];
				for (int i = 0; i < numAddresses; i++) {
					integers[i] = mockAddressCounter;
				}
			}
			addIntegers(integers);
		}

		void addIntegers(int[] integers) {
			offsets.add(nextOffset);
			intArrays.add(integers);
			nextOffset += 4 * integers.length;
		}

		List<Integer> getOffsets() {
			return offsets;
		}

		void finalizeMemory() {
			byte[] bytes = new byte[nextOffset];
			for (int index = 0; index < offsets.size(); index++) {
				addBytesForIntegers(intArrays.get(index), bytes, offsets.get(index));
			}
			memory = new CppCompositeTestMemory(bytes);
			AddressIterator iter = memory.getAddresses(true);
			if (!iter.hasNext()) {
				return;
			}
			Address address = iter.next();
			for (Integer offset : offsets) {
				addresses.add(address.add(offset));
			}
		}

		Memory getMemory() {
			return memory;
		}

		List<Address> getAddresses() {
			return addresses;
		}

		private static class CppCompositeTestMemory extends MyTestMemory {
			public CppCompositeTestMemory(byte[] bytes) {
				super(bytes);
			}

			@Override
			public int getInt(Address addr) throws MemoryAccessException {
				byte bytes[] = new byte[4];
				int num = getBytes(addr, bytes, 0, 4);
				assertEquals(num, 4);
				return LittleEndianDataConverter.INSTANCE.getInt(bytes);
			}

			@Override
			public long getLong(Address addr) throws MemoryAccessException {
				byte bytes[] = new byte[8];
				int num = getBytes(addr, bytes, 0, 8);
				assertEquals(num, 8);
				return LittleEndianDataConverter.INSTANCE.getLong(bytes);
			}
		}
	}

	static void createVxTables() {
		MemoryPreparer preparer32 = new MemoryPreparer();
		MemoryPreparer preparer64 = new MemoryPreparer();

		vbtSymbols = new ArrayList<>();
		vftSymbols = new ArrayList<>();

		//==========================================================================================

		vbtSymbols.add("??_8A@ANS@@7B@");
		preparer32.addIntegers(new int[] { -4, 8, 16 });
		preparer64.addIntegers(new int[] { -8, 16, 32 });

		vbtSymbols.add("??_8B@BNS@@7B@");
		preparer32.addIntegers(new int[] { -4, 8, 16 });
		preparer64.addIntegers(new int[] { -8, 16, 32 });

		vbtSymbols.add("??_8C@CNS@@7B@");
		preparer32.addIntegers(new int[] { -4, 8, 16, 24, 32 });
		preparer64.addIntegers(new int[] { -8, 16, 32, 48, 64 });

		vbtSymbols.add("??_8D@DNS@@7BC@CNS@@@");
		preparer32.addIntegers(new int[] { -4, 36, 44, 52, 60 });
		preparer64.addIntegers(new int[] { -8, 72, 88, 104, 120 });

		vbtSymbols.add("??_8D@DNS@@7BA@ANS@@@");
		preparer32.addIntegers(new int[] { -4, 24, 32 });
		preparer64.addIntegers(new int[] { -8, 48, 64 });

		vbtSymbols.add("??_8D@DNS@@7BB@BNS@@@");
		preparer32.addIntegers(new int[] { -4, 28, 36 });
		preparer64.addIntegers(new int[] { -8, 56, 72 });

		vbtSymbols.add("??_8E@ENS@@7BA@ANS@@@");
		preparer32.addIntegers(new int[] { -4, 12, 20, 28, 36, 44 });
		preparer64.addIntegers(new int[] { -8, 24, 40, 56, 72, 88 });

		vbtSymbols.add("??_8E@ENS@@7BB@BNS@@@");
		preparer32.addIntegers(new int[] { -4, -20, -12 });
		preparer64.addIntegers(new int[] { -8, -40, -24 });

		vbtSymbols.add("??_8F@FNS@@7B@");
		preparer32.addIntegers(new int[] { 0, 8 });
		preparer64.addIntegers(new int[] { 0, 16 });

		vbtSymbols.add("??_8G@GNS@@7B@");
		preparer32.addIntegers(new int[] { 0, 12 });
		preparer64.addIntegers(new int[] { 0, 24 });

		vbtSymbols.add("??_8H@HNS@@7B@");
		preparer32.addIntegers(new int[] { 0, 12 });
		preparer64.addIntegers(new int[] { 0, 24 });

		vbtSymbols.add("??_8I@INS@@7BG@GNS@@@");
		preparer32.addIntegers(new int[] { 0, 28 });
		preparer64.addIntegers(new int[] { 0, 56 });

		vbtSymbols.add("??_8I@INS@@7BH@HNS@@@");
		preparer32.addIntegers(new int[] { 0, 16 });
		preparer64.addIntegers(new int[] { 0, 32 });

		vbtSymbols.add("??_8J@JNS@@7B@");
		preparer32.addIntegers(new int[] { 0, 8 });
		preparer64.addIntegers(new int[] { 0, 16 });

		vbtSymbols.add("??_8K@KNS@@7B@");
		preparer32.addIntegers(new int[] { 0, 12 });
		preparer64.addIntegers(new int[] { 0, 24 });

		vbtSymbols.add("??_8L@LNS@@7B@");
		preparer32.addIntegers(new int[] { 0, 16 });
		preparer64.addIntegers(new int[] { 0, 32 });

		vbtSymbols.add("??_8M@MNS@@7BA@ANS@@E@ENS@@@");
		preparer32.addIntegers(new int[] { -4, 100, 108, 116, 124, 132 });
		preparer64.addIntegers(new int[] { -8, 200, 216, 232, 248, 264 });

		vbtSymbols.add("??_8M@MNS@@7BC@CNS@@@");
		preparer32.addIntegers(new int[] { -4, 84, 92, 100, 108 });
		preparer64.addIntegers(new int[] { -8, 168, 184, 200, 216 });

		vbtSymbols.add("??_8M@MNS@@7BA@ANS@@D@DNS@@@");
		preparer32.addIntegers(new int[] { -4, 72, 80 });
		preparer64.addIntegers(new int[] { -8, 144, 160 });

		vbtSymbols.add("??_8M@MNS@@7BB@BNS@@D@DNS@@@");
		preparer32.addIntegers(new int[] { -4, 76, 84 });
		preparer64.addIntegers(new int[] { -8, 152, 168 });

		vbtSymbols.add("??_8M@MNS@@7BG@GNS@@@");
		preparer32.addIntegers(new int[] { 0, 48 });
		preparer64.addIntegers(new int[] { 0, 96 });

		vbtSymbols.add("??_8M@MNS@@7BH@HNS@@@");
		preparer32.addIntegers(new int[] { 0, 36 });
		preparer64.addIntegers(new int[] { 0, 72 });

		vbtSymbols.add("??_8M@MNS@@7B@");
		preparer32.addIntegers(new int[] { 0, 20 });
		preparer64.addIntegers(new int[] { 0, 40 });

		vbtSymbols.add("??_8M@MNS@@7BB@BNS@@E@ENS@@@");
		preparer32.addIntegers(new int[] { -4, -20, -12 });
		preparer64.addIntegers(new int[] { -8, -40, -24 });

		//==========================================================================================
		// Below: writing one int to simulate one address for 32-bit and tow ints for 64-bit (lsb)
		// Later... mock up even better

		vftSymbols.add("??_7A1@A1NS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7A2@A2NS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7A@ANS@@6B01@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7A@ANS@@6BA1@A1NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7A@ANS@@6BA2@A2NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7B1@B1NS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7B2@B2NS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7B@BNS@@6B01@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7B@BNS@@6BB1@B1NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7B@BNS@@6BB2@B2NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7C@CNS@@6B01@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7C@CNS@@6BA1@A1NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7C@CNS@@6BA2@A2NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7C@CNS@@6BB1@B1NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7C@CNS@@6BB2@B2NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7D@DNS@@6BC@CNS@@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7D@DNS@@6BA@ANS@@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7D@DNS@@6BB@BNS@@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7D@DNS@@6BA1@A1NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7D@DNS@@6BA2@A2NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7D@DNS@@6BB1@B1NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7D@DNS@@6BB2@B2NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7E@ENS@@6BA@ANS@@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7E@ENS@@6BA1@A1NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7E@ENS@@6BA2@A2NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7E@ENS@@6BB1@B1NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7E@ENS@@6BB2@B2NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7E@ENS@@6BB@BNS@@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7F@FNS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7G@GNS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7H@HNS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7I@INS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7J@JNS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7K@KNS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7L@LNS@@6B@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7M@MNS@@6BA@ANS@@E@ENS@@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7M@MNS@@6BC@CNS@@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7M@MNS@@6BA@ANS@@D@DNS@@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7M@MNS@@6BB@BNS@@D@DNS@@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		vftSymbols.add("??_7M@MNS@@6BA1@A1NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7M@MNS@@6BA2@A2NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7M@MNS@@6BB1@B1NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7M@MNS@@6BB2@B2NS@@@");
		preparer32.addAddresses(3, false);
		preparer64.addAddresses(3, true);

		vftSymbols.add("??_7M@MNS@@6BB@BNS@@E@ENS@@@");
		preparer32.addAddresses(1, false);
		preparer64.addAddresses(1, true);

		//==========================================================================================

		preparer32.finalizeMemory();
		preparer64.finalizeMemory();

		memory32 = preparer32.getMemory();
		memory64 = preparer64.getMemory();

		vxtAddresses32 = preparer32.getAddresses();
		vxtAddresses64 = preparer64.getAddresses();

		addressByVxtMangledName32 = new HashMap<>();
		addressByVxtMangledName64 = new HashMap<>();

		if (vbtSymbols.size() + vftSymbols.size() != vxtAddresses32.size() ||
			vbtSymbols.size() + vftSymbols.size() != vxtAddresses64.size()) {
			throw new AssertException("Fatal: list sizes do not match");
		}
		int aCount = 0;
		for (String vbtSymbol : vbtSymbols) {
			addressByVxtMangledName32.put(vbtSymbol, vxtAddresses32.get(aCount));
			addressByVxtMangledName64.put(vbtSymbol, vxtAddresses64.get(aCount));
			aCount++;
		}
		for (String vftSymbol : vftSymbols) {
			addressByVxtMangledName32.put(vftSymbol, vxtAddresses32.get(aCount));
			addressByVxtMangledName64.put(vftSymbol, vxtAddresses64.get(aCount));
			aCount++;
		}
	}

	//==============================================================================================
	//==============================================================================================

	// No tests at this point because of need to rework the design

}
