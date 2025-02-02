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

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.checksums.MyTestMemory;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.SymbolPathParser;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
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

	private static int[] dummyVftMeta = new int[] { 0 };

	private static ClassID A1_ID = new ProgramClassID(CategoryPath.ROOT, sp("A1NS::A1"));
	private static ClassID A2_ID = new ProgramClassID(CategoryPath.ROOT, sp("A2NS::A2"));
	private static ClassID A_ID = new ProgramClassID(CategoryPath.ROOT, sp("ANS::A"));
	private static ClassID B1_ID = new ProgramClassID(CategoryPath.ROOT, sp("B1NS::B1"));
	private static ClassID B2_ID = new ProgramClassID(CategoryPath.ROOT, sp("B2NS::B2"));
	private static ClassID B_ID = new ProgramClassID(CategoryPath.ROOT, sp("BNS::B"));
	private static ClassID C_ID = new ProgramClassID(CategoryPath.ROOT, sp("CNS::C"));
	private static ClassID D_ID = new ProgramClassID(CategoryPath.ROOT, sp("DNS::D"));
	private static ClassID E_ID = new ProgramClassID(CategoryPath.ROOT, sp("ENS::E"));
	private static ClassID F_ID = new ProgramClassID(CategoryPath.ROOT, sp("FNS::F"));
	private static ClassID G_ID = new ProgramClassID(CategoryPath.ROOT, sp("GNS::G"));
	private static ClassID H_ID = new ProgramClassID(CategoryPath.ROOT, sp("HNS::H"));
	private static ClassID I_ID = new ProgramClassID(CategoryPath.ROOT, sp("INS::I"));
	private static ClassID J_ID = new ProgramClassID(CategoryPath.ROOT, sp("JNS::J"));
	private static ClassID K_ID = new ProgramClassID(CategoryPath.ROOT, sp("KNS::K"));
	private static ClassID L_ID = new ProgramClassID(CategoryPath.ROOT, sp("LNS::L"));
	private static ClassID M_ID = new ProgramClassID(CategoryPath.ROOT, sp("MNS::M"));

	private static Function A1NS_A1_fa1_1 = new FunctionTestDouble("A1NS::A1::fa1_1");
	private static Function A1NS_A1_fa1_2 = new FunctionTestDouble("A1NS::A1::fa1_2");
	private static Function A1NS_A1_fa1_3 = new FunctionTestDouble("A1NS::A1::fa1_3");
	private static Function A2NS_A2_fa2_1 = new FunctionTestDouble("A2NS::A2::fa2_1");
	private static Function A2NS_A2_fa2_2 = new FunctionTestDouble("A2NS::A2::fa2_2");
	private static Function A2NS_A2_fa2_3 = new FunctionTestDouble("A2NS::A2::fa2_3");
	private static Function ANS_A_fa1_1 = new FunctionTestDouble("ANS::A::fa1_1");
	private static Function ANS_A_fa2_1 = new FunctionTestDouble("ANS::A::fa2_1");
	private static Function ANS_A_fa_1 = new FunctionTestDouble("ANS::A::fa_1");
	private static Function ANS_A_fa1_1_thunkThisMinus16 =
		new FunctionTestDouble("ANS::A::fa1_1_thunkThisMinus16");
	private static Function ANS_A_fa2_1_thunkThisMinus4 =
		new FunctionTestDouble("ANS::A::fa2_1_thunkThisMinus4");
	private static Function B1NS_B1_fb1_1 = new FunctionTestDouble("B1NS::B1::fb1_1");
	private static Function B1NS_B1_fb1_2 = new FunctionTestDouble("B1NS::B1::fb1_2");
	private static Function B1NS_B1_fb1_3 = new FunctionTestDouble("B1NS::B1::fb1_3");
	private static Function B2NS_B2_fb2_1 = new FunctionTestDouble("B2NS::B2::fb2_1");
	private static Function B2NS_B2_fb2_2 = new FunctionTestDouble("B2NS::B2::fb2_2");
	private static Function B2NS_B2_fb2_3 = new FunctionTestDouble("B2NS::B2::fb2_3");
	private static Function BNS_B_fb1_1 = new FunctionTestDouble("BNS::B::fb1_1");
	private static Function BNS_B_fb2_1 = new FunctionTestDouble("BNS::B::fb2_1");
	private static Function BNS_B_fb_1 = new FunctionTestDouble("BNS::B::fb_1");
	private static Function BNS_B_fb1_1_thunkThisMinus16 =
		new FunctionTestDouble("BNS::B::fb1_1_thunkThisMinus16");
	private static Function BNS_B_fb1_1_thunkThisPlus28 =
		new FunctionTestDouble("BNS::B::fb1_1_thunkThisPlus28");
	private static Function BNS_B_fb2_1_thunkThisPlus28 =
		new FunctionTestDouble("BNS::B::fb2_1_thunkThisPlus28");
	private static Function CNS_C_fa1_2 = new FunctionTestDouble("CNS::C::fa1_2");
	private static Function CNS_C_fa2_1 = new FunctionTestDouble("CNS::C::fa2_1");
	private static Function CNS_C_fb1_2 = new FunctionTestDouble("CNS::C::fb1_2");
	private static Function CNS_C_fb2_1 = new FunctionTestDouble("CNS::C::fb2_1");
	private static Function CNS_C_fc_1 = new FunctionTestDouble("CNS::C::fc_1");
	private static Function CNS_C_fa1_2_thunkThisMinus28 =
		new FunctionTestDouble("CNS::C::fa1_2_thunkThisMinus28");
	private static Function CNS_C_fb1_2_thunkThisMinus28 =
		new FunctionTestDouble("CNS::C::fb1_2_thunkThisMinus28");
	private static Function CNS_C_fa1_2_thunkThisMinus84 =
		new FunctionTestDouble("CNS::C::fa1_2_thunkThisMinus84");
	private static Function CNS_C_fb1_2_thunkThisMinus84 =
		new FunctionTestDouble("CNS::C::fb1_2_thunkThisMinus84");
	private static Function DNS_D_fa2_1 = new FunctionTestDouble("DNS::D::fa2_1");
	private static Function DNS_D_fb2_1 = new FunctionTestDouble("DNS::D::fb2_1");
	private static Function ENS_E_fa1_1 = new FunctionTestDouble("ENS::E::fa1_1");
	private static Function FNS_F_fa1_1 = new FunctionTestDouble("FNS::F::fa1_1");
	private static Function GNS_G_fa1_1 = new FunctionTestDouble("GNS::G::fa1_1");
	private static Function HNS_H_fa1_1 = new FunctionTestDouble("HNS::H::fa1_1");
	private static Function INS_I_fa1_1 = new FunctionTestDouble("INS::I::fa1_1");
	private static Function JNS_J_fa1_1 = new FunctionTestDouble("JNS::J::fa1_1");
	private static Function KNS_K_fa1_1 = new FunctionTestDouble("KNS::K::fa1_1");
	private static Function LNS_L_fa1_1 = new FunctionTestDouble("LNS::L::fa1_1");
	private static Function N1NS_N1_fn1_1 = new FunctionTestDouble("N1NS::N1::fn1_1");
	private static Function N1NS_N1_fn1_2 = new FunctionTestDouble("N1NS::N1::fn1_2");
	private static Function N2NS_N2_fn2_1 = new FunctionTestDouble("N2NS::N2::fn2_1");
	private static Function N2NS_N2_fn2_2 = new FunctionTestDouble("N2NS::N2::fn2_2");
	private static Function MNS_M_fa1_1 = new FunctionTestDouble("MNS::M::fa1_1");
	private static Function MNS_M_fa2_1 = new FunctionTestDouble("MNS::M::fa2_1");
	private static Function MNS_M_fb1_1 = new FunctionTestDouble("MNS::M::fb1_1");
	private static Function MNS_M_fb2_1 = new FunctionTestDouble("MNS::M::fb1_2");
	private static Function MNS_M_fn1_1 = new FunctionTestDouble("MNS::M::fn1_1");

	private static Memory memory32;
	private static Memory memory64;
	private static Program program32;
	private static Program program64;
	private static List<Address> addresses32;
	private static List<Address> addresses64;

	private static List<Function> functions;
	private static Map<Function, Integer> offsetsByFunction32 = new HashMap<>();
	private static Map<Function, Integer> offsetsByFunction64 = new HashMap<>();

	private static List<String> vbtSymbols = new ArrayList<>();
	private static List<String> vftSymbols = new ArrayList<>();

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

		createMemoryAndPrograms();

		mVxtManager32 = new MsftVxtManager(ctm32, program32);
		mVxtManager64 = new MsftVxtManager(ctm64, program64);

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

	private static class MyStubFunctionManager extends StubFunctionManager {

		private Map<Address, Function> myFunctions;

		private MyStubFunctionManager() {
			myFunctions = new HashMap<>();
		}

		private void addFunction(Address address, Function function) {
			myFunctions.put(address, function);
		}

		@Override
		public Function getFunctionAt(Address entryPoint) {
			return myFunctions.get(entryPoint);
		}
	}

	private static class MyStubProgram extends StubProgram {
		private Memory myMemory;
		private FunctionManager myFunctionManager;

		private MyStubProgram(Memory mem, FunctionManager fm) {
			this.myMemory = mem;
			this.myFunctionManager = fm;
		}

		@Override
		public FunctionManager getFunctionManager() {
			return myFunctionManager;
		}

		@Override
		public Memory getMemory() {
			return myMemory;
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

	private static class MemoryPreparer {
		private int nextOffset = 0;
		private List<int[]> intArrays = new ArrayList<>();
		private List<Integer> myOffsets = new ArrayList<>();
		private List<Address> addresses = new ArrayList<>();
		private MyTestMemory memory = null;
		private int mockAddressCounter = 0;

		private int addAddresses(int[] offsetsArg, boolean is64bit) {
			int[] integers;
			int startCount = mockAddressCounter;
			if (is64bit) {
				integers = new int[offsetsArg.length * 2];
				for (int i = 0; i < offsetsArg.length; i++) {
					integers[i * 2] = offsetsArg[i];
					integers[i * 2 + 1] = 0;
				}
			}
			else {
				integers = offsetsArg;
			}
			addIntegers(integers);
			return startCount;
		}

		private int addAddresses(int numAddresses, boolean is64bit) {
			int[] integers;
			int startCount = mockAddressCounter;
			if (is64bit) {
				integers = new int[numAddresses * 2];
				for (int i = 0; i < numAddresses; i++) {
					integers[i * 2] = mockAddressCounter++;
					integers[i * 2 + 1] = 0;
				}
			}
			else {
				integers = new int[numAddresses];
				for (int i = 0; i < numAddresses; i++) {
					integers[i] = mockAddressCounter++;
				}
			}
			addIntegers(integers);
			return startCount;
		}

		private int getNextOffset() {
			return nextOffset;
		}

		private void addIntegers(int[] integers) {
			myOffsets.add(nextOffset);
			intArrays.add(integers);
			nextOffset += 4 * integers.length;
		}

		private List<Integer> getOffsets() {
			return myOffsets;
		}

		private void finalizeMemory() {
			byte[] bytes = new byte[nextOffset];
			for (int index = 0; index < myOffsets.size(); index++) {
				addBytesForIntegers(intArrays.get(index), bytes, myOffsets.get(index));
			}
			memory = new CppCompositeTestMemory(bytes);
			AddressIterator iter = memory.getAddresses(true);
			if (!iter.hasNext()) {
				return;
			}
			Address address = iter.next();
			for (Integer offset : myOffsets) {
				addresses.add(address.add(offset));
			}
		}

		private Memory getMemory() {
			return memory;
		}

		private List<Address> getAddresses() {
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

	/**
	 * Prepares Virtual Function Table for 32-bit and 64-bit memory models
	 * @param preparer32 the MemoryPreparer for 32-bit
	 * @param preparer64 the MemoryPreparer for 64-bit
	 * @param mangledName the mangled name for the table
	 * @param functionsArg varargs of functions for the table
	 */
	private static void prepareVfts(MemoryPreparer preparer32, MemoryPreparer preparer64,
			String mangledName, Function... functionsArg) {
		int offsets32[] = new int[functionsArg.length];
		int offsets64[] = new int[functionsArg.length];
		for (int i = 0; i < functionsArg.length; i++) {
			Function fn = functionsArg[i];
			offsets32[i] = offsetsByFunction32.get(fn);
			offsets64[i] = offsetsByFunction32.get(fn);
		}
		preparer32.addAddresses(dummyVftMeta, false);
		preparer64.addAddresses(dummyVftMeta, true);
		vftSymbols.add(mangledName);
		preparer32.addAddresses(offsets32, false);
		preparer64.addAddresses(offsets64, true);
	}

	private static void createMemoryAndPrograms() {
		MemoryPreparer preparer32 = new MemoryPreparer();
		MemoryPreparer preparer64 = new MemoryPreparer();

		vbtSymbols = new ArrayList<>();
		vftSymbols = new ArrayList<>();

		//==========================================================================================

		functions = List.of(A1NS_A1_fa1_1, A1NS_A1_fa1_2, A1NS_A1_fa1_3, A2NS_A2_fa2_1,
			A2NS_A2_fa2_2, A2NS_A2_fa2_3, ANS_A_fa1_1, ANS_A_fa2_1, ANS_A_fa_1,
			ANS_A_fa1_1_thunkThisMinus16, ANS_A_fa2_1_thunkThisMinus4, B1NS_B1_fb1_1, B1NS_B1_fb1_2,
			B1NS_B1_fb1_3, B2NS_B2_fb2_1, B2NS_B2_fb2_2, B2NS_B2_fb2_3, BNS_B_fb1_1, BNS_B_fb2_1,
			BNS_B_fb_1, BNS_B_fb1_1_thunkThisMinus16, BNS_B_fb1_1_thunkThisPlus28,
			BNS_B_fb2_1_thunkThisPlus28, CNS_C_fa1_2, CNS_C_fa2_1, CNS_C_fb1_2, CNS_C_fb2_1,
			CNS_C_fc_1, CNS_C_fa1_2_thunkThisMinus28, CNS_C_fb1_2_thunkThisMinus28,
			CNS_C_fa1_2_thunkThisMinus84, CNS_C_fb1_2_thunkThisMinus84, DNS_D_fa2_1, DNS_D_fb2_1,
			ENS_E_fa1_1, FNS_F_fa1_1, GNS_G_fa1_1, HNS_H_fa1_1, INS_I_fa1_1, JNS_J_fa1_1,
			KNS_K_fa1_1, LNS_L_fa1_1, N1NS_N1_fn1_1, N1NS_N1_fn1_2, N2NS_N2_fn2_1, N2NS_N2_fn2_2,
			MNS_M_fa1_1, MNS_M_fa2_1, MNS_M_fb1_1, MNS_M_fb2_1, MNS_M_fn1_1);

		for (Function f : functions) {
			int addressOffset32 = preparer32.getNextOffset();
			int addressOffset64 = preparer64.getNextOffset();
			int count32 = preparer32.addAddresses(1, false);
			int count64 = preparer64.addAddresses(1, true);
			assertEquals(count32, count64);
			offsetsByFunction32.put(f, addressOffset32);
			offsetsByFunction64.put(f, addressOffset64);
		}

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
		preparer32.addIntegers(new int[] { -4, 108, 116, 124, 132, 140, 100, 152 });
		preparer64.addIntegers(new int[] { -8, 216, 232, 248, 264, 280, 200, 304 });

		vbtSymbols.add("??_8M@MNS@@7BC@CNS@@@");
		preparer32.addIntegers(new int[] { -4, 92, 100, 108, 116 });
		preparer64.addIntegers(new int[] { -8, 184, 200, 216, 232 });

		vbtSymbols.add("??_8M@MNS@@7BA@ANS@@D@DNS@@@");
		preparer32.addIntegers(new int[] { -4, 80, 88 });
		preparer64.addIntegers(new int[] { -8, 160, 176 });

		vbtSymbols.add("??_8M@MNS@@7BB@BNS@@D@DNS@@@");
		preparer32.addIntegers(new int[] { -4, 84, 92 });
		preparer64.addIntegers(new int[] { -8, 168, 184 });

		vbtSymbols.add("??_8M@MNS@@7BG@GNS@@@");
		preparer32.addIntegers(new int[] { 0, 56 });
		preparer64.addIntegers(new int[] { 0, 112 });

		vbtSymbols.add("??_8M@MNS@@7BH@HNS@@@");
		preparer32.addIntegers(new int[] { 0, 44 });
		preparer64.addIntegers(new int[] { 0, 88 });

		vbtSymbols.add("??_8M@MNS@@7B@");
		preparer32.addIntegers(new int[] { 0, 28 });
		preparer64.addIntegers(new int[] { 0, 56 });

		vbtSymbols.add("??_8M@MNS@@7BB@BNS@@E@ENS@@@");
		preparer32.addIntegers(new int[] { -4, -20, -12 });
		preparer64.addIntegers(new int[] { -8, -40, -24 });

		//==========================================================================================
		// Below: writing one int to simulate one address for 32-bit and tow ints for 64-bit (lsb)
		// Later... mock up even better

		prepareVfts(preparer32, preparer64, "??_7A1@A1NS@@6B@", A1NS_A1_fa1_1, A1NS_A1_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7A2@A2NS@@6B@", A2NS_A2_fa2_1, A2NS_A2_fa2_2,
			A2NS_A2_fa2_3);

		prepareVfts(preparer32, preparer64, "??_7A@ANS@@6B01@@", ANS_A_fa_1);

		prepareVfts(preparer32, preparer64, "??_7A@ANS@@6BA1@A1NS@@@", ANS_A_fa1_1, A1NS_A1_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7A@ANS@@6BA2@A2NS@@@", ANS_A_fa2_1, A2NS_A2_fa2_2,
			A2NS_A2_fa2_3);

		prepareVfts(preparer32, preparer64, "??_7B1@B1NS@@6B@", B1NS_B1_fb1_1, B1NS_B1_fb1_2,
			B1NS_B1_fb1_3);

		prepareVfts(preparer32, preparer64, "??_7B2@B2NS@@6B@", B2NS_B2_fb2_1, B2NS_B2_fb2_2,
			B2NS_B2_fb2_3);

		prepareVfts(preparer32, preparer64, "??_7B@BNS@@6B01@@", BNS_B_fb_1);

		prepareVfts(preparer32, preparer64, "??_7B@BNS@@6BB1@B1NS@@@", BNS_B_fb1_1, B1NS_B1_fb1_2,
			B1NS_B1_fb1_3);

		prepareVfts(preparer32, preparer64, "??_7B@BNS@@6BB2@B2NS@@@", BNS_B_fb2_1, B2NS_B2_fb2_2,
			B2NS_B2_fb2_3);

		prepareVfts(preparer32, preparer64, "??_7C@CNS@@6B01@@", CNS_C_fc_1);

		prepareVfts(preparer32, preparer64, "??_7C@CNS@@6BA1@A1NS@@@", A1NS_A1_fa1_1, CNS_C_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7C@CNS@@6BA2@A2NS@@@", CNS_C_fa2_1, A2NS_A2_fa2_2,
			A2NS_A2_fa2_3);

		prepareVfts(preparer32, preparer64, "??_7C@CNS@@6BB1@B1NS@@@", B1NS_B1_fb1_1, CNS_C_fb1_2,
			B1NS_B1_fb1_3);

		prepareVfts(preparer32, preparer64, "??_7C@CNS@@6BB2@B2NS@@@", CNS_C_fb2_1, B2NS_B2_fb2_2,
			B2NS_B2_fb2_3);

		prepareVfts(preparer32, preparer64, "??_7D@DNS@@6BC@CNS@@@", CNS_C_fc_1);

		prepareVfts(preparer32, preparer64, "??_7D@DNS@@6BA@ANS@@@", ANS_A_fa_1);

		prepareVfts(preparer32, preparer64, "??_7D@DNS@@6BB@BNS@@@", BNS_B_fb_1);

		prepareVfts(preparer32, preparer64, "??_7D@DNS@@6BA1@A1NS@@@", ANS_A_fa1_1_thunkThisMinus16,
			CNS_C_fa1_2_thunkThisMinus28, A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7D@DNS@@6BA2@A2NS@@@", DNS_D_fa2_1, A2NS_A2_fa2_2,
			A2NS_A2_fa2_3);

		prepareVfts(preparer32, preparer64, "??_7D@DNS@@6BB1@B1NS@@@", BNS_B_fb1_1_thunkThisMinus16,
			CNS_C_fb1_2_thunkThisMinus28, B1NS_B1_fb1_3);

		prepareVfts(preparer32, preparer64, "??_7D@DNS@@6BB2@B2NS@@@", DNS_D_fb2_1, B2NS_B2_fb2_2,
			B2NS_B2_fb2_3);

		prepareVfts(preparer32, preparer64, "??_7E@ENS@@6BA@ANS@@@", ANS_A_fa_1);

		prepareVfts(preparer32, preparer64, "??_7E@ENS@@6BA1@A1NS@@@", ENS_E_fa1_1, A1NS_A1_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7E@ENS@@6BA2@A2NS@@@", ANS_A_fa2_1_thunkThisMinus4,
			A2NS_A2_fa2_2, A2NS_A2_fa2_3);

		prepareVfts(preparer32, preparer64, "??_7E@ENS@@6BB1@B1NS@@@", BNS_B_fb1_1_thunkThisPlus28,
			B1NS_B1_fb1_2, B1NS_B1_fb1_3);

		prepareVfts(preparer32, preparer64, "??_7E@ENS@@6BB2@B2NS@@@", BNS_B_fb2_1_thunkThisPlus28,
			B2NS_B2_fb2_2, B2NS_B2_fb2_3);

		prepareVfts(preparer32, preparer64, "??_7E@ENS@@6BB@BNS@@@", BNS_B_fb_1);

		prepareVfts(preparer32, preparer64, "??_7F@FNS@@6B@", FNS_F_fa1_1, A1NS_A1_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7G@GNS@@6B@", GNS_G_fa1_1, A1NS_A1_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7H@HNS@@6B@", HNS_H_fa1_1, A1NS_A1_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7I@INS@@6B@", INS_I_fa1_1, A1NS_A1_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7J@JNS@@6B@", JNS_J_fa1_1, A1NS_A1_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7K@KNS@@6B@", KNS_K_fa1_1, A1NS_A1_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7L@LNS@@6B@", LNS_L_fa1_1, A1NS_A1_fa1_2,
			A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7N1@N1NS@@6B@", N1NS_N1_fn1_1, N1NS_N1_fn1_2);

		prepareVfts(preparer32, preparer64, "??_7N2@N2NS@@6B@", N2NS_N2_fn2_1, N2NS_N2_fn2_2);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BA@ANS@@E@ENS@@@", ANS_A_fa_1);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BC@CNS@@@", CNS_C_fc_1);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BA@ANS@@D@DNS@@@", ANS_A_fa_1);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BB@BNS@@D@DNS@@@", BNS_B_fb_1);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BN1@N1NS@@@", MNS_M_fn1_1, N1NS_N1_fn1_2);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BA1@A1NS@@@", MNS_M_fa1_1,
			CNS_C_fa1_2_thunkThisMinus84, A1NS_A1_fa1_3);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BA2@A2NS@@@", MNS_M_fa2_1, A2NS_A2_fa2_2,
			A2NS_A2_fa2_3);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BB1@B1NS@@@", MNS_M_fb1_1,
			CNS_C_fb1_2_thunkThisMinus84, B1NS_B1_fb1_3);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BB2@B2NS@@@", MNS_M_fb2_1, B2NS_B2_fb2_2,
			B2NS_B2_fb2_3);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BB@BNS@@E@ENS@@@", BNS_B_fb_1);

		prepareVfts(preparer32, preparer64, "??_7M@MNS@@6BN2@N2NS@@@", N2NS_N2_fn2_1,
			N2NS_N2_fn2_2);

		//==========================================================================================

		preparer32.finalizeMemory();
		preparer64.finalizeMemory();

		memory32 = preparer32.getMemory();
		memory64 = preparer64.getMemory();

		MyStubFunctionManager functionManager32 = new MyStubFunctionManager();
		MyStubFunctionManager functionManager64 = new MyStubFunctionManager();

		program32 = new MyStubProgram(memory32, functionManager32);
		program64 = new MyStubProgram(memory64, functionManager64);

		addresses32 = preparer32.getAddresses();
		addresses64 = preparer64.getAddresses();

		addressByVxtMangledName32 = new HashMap<>();
		addressByVxtMangledName64 = new HashMap<>();

		if (functions.size() + vbtSymbols.size() + 2 * vftSymbols.size() != addresses32.size() ||
			functions.size() + vbtSymbols.size() + 2 * vftSymbols.size() != addresses64.size()) {
			throw new AssertException("Fatal: list sizes do not match");
		}
		int accumulatedCount = 0;
		for (Function f : functions) {
			functionManager32.addFunction(addresses32.get(accumulatedCount), f);
			functionManager64.addFunction(addresses64.get(accumulatedCount), f);
			accumulatedCount++;
		}
		for (String vbtSymbol : vbtSymbols) {
			addressByVxtMangledName32.put(vbtSymbol, addresses32.get(accumulatedCount));
			addressByVxtMangledName64.put(vbtSymbol, addresses64.get(accumulatedCount));
			accumulatedCount++;
		}
		for (String vftSymbol : vftSymbols) {
			// skip an extra for each meta
			addressByVxtMangledName32.put(vftSymbol, addresses32.get(accumulatedCount + 1));
			addressByVxtMangledName64.put(vftSymbol, addresses64.get(accumulatedCount + 1));
			accumulatedCount += 2;
		}
	}

	//==============================================================================================
	//==============================================================================================

	// Not many tests at this point because of need to rework the design of finding tables
	//  based on parentage (which is not the necessarily the same as nesting in the layout).

	@Test
	public void testMVbt_temp() throws Exception {

		ProgramVirtualBaseTable vbt;

		vbt = (ProgramVirtualBaseTable) mVxtManager32.findVbt(M_ID, List.of(M_ID));
		assertEquals(addresses32.get(73), vbt.getAddress());
		// Not certain that this one is a valid query... depends on the design work that needs
		//  to be done
//		vbt = (ProgramVirtualBaseTable) mVxtManager32.findVbt(mId, List.of(eId));
//		assertEquals(addresses32.get(73), vbt.getAddress());
	}

	//==============================================================================================
	@Test
	public void testMVft_temp() throws Exception {

		ProgramVirtualFunctionTable vft;
		Address address;
		Function function;

		// Test with and without parentage referencing owner type.  We are treating them as the
		//  same for now.  If we can tease out more information or encounter difficulties, we
		//  need to split these out accordingly (within the work of findVft (and findVbt)).
		vft = (ProgramVirtualFunctionTable) mVxtManager32.findVft(A_ID, List.of(A_ID));
		assertEquals(addresses32.get(80), vft.getAddress());
		address = vft.getAddress(0);
		function = program32.getFunctionManager().getFunctionAt(address);
		assertEquals(ANS_A_fa_1, function);
		function.getName().equals(ANS_A_fa_1.getName());
		vft = (ProgramVirtualFunctionTable) mVxtManager32.findVft(A_ID, List.of());
		assertEquals(addresses32.get(80), vft.getAddress());
	}

}
