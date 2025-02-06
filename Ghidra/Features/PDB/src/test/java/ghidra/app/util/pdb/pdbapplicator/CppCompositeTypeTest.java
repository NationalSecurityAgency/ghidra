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

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Ignore;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.checksums.MyTestMemory;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.classtype.*;
import ghidra.program.model.StubFunctionManager;
import ghidra.program.model.StubProgram;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Unit tests for the {@link CppCompositeType}.
 */
public class CppCompositeTypeTest extends AbstractGenericTest {

	private static MessageLog log = new MessageLog();
	private static TaskMonitor monitor = TaskMonitor.DUMMY;

	private static MyTestDummyDataTypeManager dtm32;
	private static MyTestDummyDataTypeManager dtm64;
	// Didn't intend to modify this class to need these, but need them while modifying MsftVxtManager
	// to use them
	private static ClassTypeManager ctm32;
	private static ClassTypeManager ctm64;
	private static Memory memory32;
	private static Memory memory64;
	private static Program program32;
	private static Program program64;
	private static Map<String, Address> addressByMangledName32;
	private static Map<String, Address> addressByMangledName64;
	private static DataType vftptr32;
	private static DataType vftptr64;
	private static DataType vbtptr32;
	private static DataType vbtptr64;
	private static MsftVxtManager msftVxtManager32;
	private static MsftVxtManager msftVxtManager64;
	private static VxtManager vxtManager32;
	private static VxtManager vxtManager64;
	// Note: Currently all test have expected results based on up the CLASS_HIERARCHY layout.
	private static ObjectOrientedClassLayout classLayoutChoice =
		ObjectOrientedClassLayout.CLASS_HIERARCHY;

	// Note that we would not normally want to share these attributes amongst classes and their
	// members, as we might want to change one without changing all.  However, we are using this
	// for testing, and thus are creating this static item.
	private static ClassFieldAttributes publicVirtualAttributes =
		ClassFieldAttributes.get(Access.PUBLIC, Property.VIRTUAL);
	private static ClassFieldAttributes publicDirectAttributes =
		ClassFieldAttributes.get(Access.PUBLIC, Property.BLANK);

	static ClassFieldAttributes TEST_ATTS =
		ClassFieldAttributes.get(Access.PUBLIC, Property.UNKNOWN);

	static {
		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl();
		bitFieldPacking.setUseMSConvention(true);

		// DataOrganization based on x86win.cspec
		// The DataOrganizationImpl currently has defaults of a 32-bit windows cspec, but could
		// change in the future.
		DataOrganizationImpl dataOrg32 = DataOrganizationImpl.getDefaultOrganization(null);
		dtm32 = new MyTestDummyDataTypeManager(dataOrg32);

		// DataOrganization based on x86-64-win.cspec
		DataOrganizationImpl dataOrg64 = DataOrganizationImpl.getDefaultOrganization(null);
		DataOrganizationTestUtils.initDataOrganizationWindows64BitX86(dataOrg64);
		dtm64 = new MyTestDummyDataTypeManager(dataOrg64);

		// Didn't intend to modify this class to need these, but need them while modifying
		//  MsftVxtManager to use them
		ctm32 = new ClassTypeManager(dtm32);
		ctm64 = new ClassTypeManager(dtm64);

		vftptr32 = new PointerDataType(new PointerDataType(dtm32));
		vftptr64 = new PointerDataType(new PointerDataType(dtm64));
		vbtptr32 = new PointerDataType(new IntegerDataType(dtm32));
		vbtptr64 = new PointerDataType(new IntegerDataType(dtm64));
//		// might not be accurate lengths because not yet resolved
//		System.out.println("vftptr32 size: " + vftptr32.getLength());
//		System.out.println("vftptr64 size: " + vftptr64.getLength());
//		System.out.println("vbtptr32 size: " + vbtptr32.getLength());
//		System.out.println("vbtptr64 size: " + vbtptr64.getLength());

		createVbTables();

		msftVxtManager32 = new MsftVxtManager(ctm32, program32);
		msftVxtManager64 = new MsftVxtManager(ctm64, program64);
		try {
			msftVxtManager32.createVirtualTables(CategoryPath.ROOT, addressByMangledName32, log,
				monitor);
			msftVxtManager64.createVirtualTables(CategoryPath.ROOT, addressByMangledName64, log,
				monitor);
		}
		catch (CancelledException e) {
			// do nothing
		}
		vxtManager32 = new VxtManager(ctm32);
		vxtManager64 = new VxtManager(ctm64);

	}

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
			return null;
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

	static void createVbTables() {
		MemoryPreparer preparer32 = new MemoryPreparer();
		MemoryPreparer preparer64 = new MemoryPreparer();
		List<String> vbtSymbols = new ArrayList<>();

		vbtSymbols.add("??_8G@@7B@");
		preparer32.addIntegers(new int[] { 0, 8 });
		preparer64.addIntegers(new int[] { 0, 16 });

		vbtSymbols.add("??_8H@@7B@");
		preparer32.addIntegers(new int[] { 0, 8 });
		preparer64.addIntegers(new int[] { 0, 16 });

		vbtSymbols.add("??_8GG1@@7B@");
		preparer32.addIntegers(new int[] { 0, 8 });
		preparer64.addIntegers(new int[] { 0, 16 });

		vbtSymbols.add("??_8GG2@@7B@");
		preparer32.addIntegers(new int[] { 0, 8 });
		preparer64.addIntegers(new int[] { 0, 16 });

		vbtSymbols.add("??_8GG3@@7B@");
		preparer32.addIntegers(new int[] { 0, 8 });
		preparer64.addIntegers(new int[] { 0, 16 });

		vbtSymbols.add("??_8GG4@@7B@");
		preparer32.addIntegers(new int[] { 0, 8 });
		preparer64.addIntegers(new int[] { 0, 16 });

		vbtSymbols.add("??_8I@@7BG@@@");
		preparer32.addIntegers(new int[] { 0, 20 });
		preparer64.addIntegers(new int[] { 0, 40 });

		vbtSymbols.add("??_8I@@7BH@@@");
		preparer32.addIntegers(new int[] { 0, 12 });
		preparer64.addIntegers(new int[] { 0, 20 });

		// TODO: do not delete... these are for future use.
//		vbtSymbols.add("??_8GX1@@7B@");
//		preparer32.addIntegers(new int[] { 0, 4 });
//		preparer64.addIntegers(new int[] { 0, 8});

//		vbtSymbols.add("??_8HX1@@7B@");
//		preparer32.addIntegers(new int[] { 0, 4 });
//		preparer64.addIntegers(new int[] { 0, 8});

//		vbtSymbols.add("??_8IX1@@7BGX1@@@");
//		preparer32.addIntegers(new int[] { 0, 12 });
//		preparer64.addIntegers(new int[] { 0, 24});

//		vbtSymbols.add("??_8IX1@@7BHX1@@@");
//		preparer32.addIntegers(new int[] { 0, 8 });
//		preparer64.addIntegers(new int[] { 0, 16});

		vbtSymbols.add("??_8G1@@7B@");
		preparer32.addIntegers(new int[] { 0, 8, 12 });
		preparer64.addIntegers(new int[] { 0, 16, 20 });

		vbtSymbols.add("??_8H1@@7B@");
		preparer32.addIntegers(new int[] { 0, 8, 12 });
		preparer64.addIntegers(new int[] { 0, 16, 20 });

		vbtSymbols.add("??_8I1@@7BG1@@@");
		preparer32.addIntegers(new int[] { 0, 20, 24 });
		preparer64.addIntegers(new int[] { 0, 40, 44 });

		vbtSymbols.add("??_8I1@@7BH@@@");
		preparer32.addIntegers(new int[] { 0, 12 });
		preparer64.addIntegers(new int[] { 0, 24 });

		vbtSymbols.add("??_8I2@@7BG@@@");
		preparer32.addIntegers(new int[] { 0, 20, 24 });
		preparer64.addIntegers(new int[] { 0, 40, 44 });

		vbtSymbols.add("??_8I2@@7BH1@@@");
		preparer32.addIntegers(new int[] { 0, 16, 12 });
		preparer64.addIntegers(new int[] { 0, 28, 24 });

		vbtSymbols.add("??_8I3@@7BG1@@@");
		preparer32.addIntegers(new int[] { 0, 20, 24 });
		preparer64.addIntegers(new int[] { 0, 40, 44 });

		vbtSymbols.add("??_8I3@@7BH1@@@");
		preparer32.addIntegers(new int[] { 0, 16, 12 });
		preparer64.addIntegers(new int[] { 0, 28, 24 });

		vbtSymbols.add("??_8I4@@7B@");
		preparer32.addIntegers(new int[] { 0, 12, 16 });
		preparer64.addIntegers(new int[] { 0, 24, 28 });

		vbtSymbols.add("??_8I5@@7B@");
		preparer32.addIntegers(new int[] { 0, 16, 12 });
		preparer64.addIntegers(new int[] { 0, 28, 24 });

		vbtSymbols.add("??_8J1@@7BG1@@@");
		preparer32.addIntegers(new int[] { 0, 44, 48 });
		preparer64.addIntegers(new int[] { 0, 88, 92 });

		vbtSymbols.add("??_8J1@@7BH@@@");
		preparer32.addIntegers(new int[] { 0, 36 });
		preparer64.addIntegers(new int[] { 0, 72 });

		vbtSymbols.add("??_8J1@@7BG@@@");
		preparer32.addIntegers(new int[] { 0, 24, 28 });
		preparer64.addIntegers(new int[] { 0, 48, 52 });

		vbtSymbols.add("??_8J1@@7BH1@@@");
		preparer32.addIntegers(new int[] { 0, 20, 16 });
		preparer64.addIntegers(new int[] { 0, 36, 32 });

		vbtSymbols.add("??_8J2@@7BG@@@");
		preparer32.addIntegers(new int[] { 0, 44, 48 });
		preparer64.addIntegers(new int[] { 0, 88, 92 });

		vbtSymbols.add("??_8J2@@7BH1@@@");
		preparer32.addIntegers(new int[] { 0, 40, 36 });
		preparer64.addIntegers(new int[] { 0, 76, 72 });

		vbtSymbols.add("??_8J2@@7BG1@@@");
		preparer32.addIntegers(new int[] { 0, 24, 28 });
		preparer64.addIntegers(new int[] { 0, 48, 52 });

		vbtSymbols.add("??_8J2@@7BH@@@");
		preparer32.addIntegers(new int[] { 0, 16 });
		preparer64.addIntegers(new int[] { 0, 32 });

		vbtSymbols.add("??_8J3@@7BG@@@");
		preparer32.addIntegers(new int[] { 0, 52, 56 });
		preparer64.addIntegers(new int[] { 0, 96, 100 });

		vbtSymbols.add("??_8J3@@7BH1@@@");
		preparer32.addIntegers(new int[] { 0, 48, 44 });
		preparer64.addIntegers(new int[] { 0, 84, 80 });

		vbtSymbols.add("??_8J3@@7BG1@@@");
		preparer32.addIntegers(new int[] { 0, 32, 36 });
		preparer64.addIntegers(new int[] { 0, 56, 60 });

		vbtSymbols.add("??_8J3@@7BH@@@");
		preparer32.addIntegers(new int[] { 0, 24 });
		preparer64.addIntegers(new int[] { 0, 40 });

		vbtSymbols.add("??_8J4@@7BG1@@@");
		preparer32.addIntegers(new int[] { 0, 60, 64, 68, 72, 76, 84 });
		preparer64.addIntegers(new int[] { 0, 112, 116, 120, 124, 128, 144 });

		vbtSymbols.add("??_8J4@@7BH1@@@");
		preparer32.addIntegers(new int[] { 0, 56, 52 });
		preparer64.addIntegers(new int[] { 0, 100, 96 });

		vbtSymbols.add("??_8J4@@7BGG1@@@");
		preparer32.addIntegers(new int[] { 0, 48 });
		preparer64.addIntegers(new int[] { 0, 80 });

		vbtSymbols.add("??_8J4@@7BG@@@");
		preparer32.addIntegers(new int[] { 0, 32 });
		preparer64.addIntegers(new int[] { 0, 56 });

		vbtSymbols.add("??_8J4@@7BH@@@");
		preparer32.addIntegers(new int[] { 0, 24 });
		preparer64.addIntegers(new int[] { 0, 40 });

		vbtSymbols.add("??_8J4@@7BGG2@@@");
		preparer32.addIntegers(new int[] { 0, -4 });
		preparer64.addIntegers(new int[] { 0, -4 });

		vbtSymbols.add("??_8J4@@7BGG3@@@");
		preparer32.addIntegers(new int[] { 0, -12 });
		preparer64.addIntegers(new int[] { 0, -20 });

		vbtSymbols.add("??_8J5@@7BG1@@@");
		preparer32.addIntegers(new int[] { 0, 80, 84, 60, 64, 72, 88 });
		preparer64.addIntegers(new int[] { 0, 152, 156, 112, 120, 136, 160 });

		vbtSymbols.add("??_8J5@@7BH1@@@");
		preparer32.addIntegers(new int[] { 0, 76, 72 });
		preparer64.addIntegers(new int[] { 0, 140, 136 });

		vbtSymbols.add("??_8J5@@7BGG1@@@");
		preparer32.addIntegers(new int[] { 0, 68 });
		preparer64.addIntegers(new int[] { 0, 120 });

		vbtSymbols.add("??_8J5@@7BG@@@");
		preparer32.addIntegers(new int[] { 0, 52 });
		preparer64.addIntegers(new int[] { 0, 96 });

		vbtSymbols.add("??_8J5@@7BH@@@");
		preparer32.addIntegers(new int[] { 0, 44 });
		preparer64.addIntegers(new int[] { 0, 80 });

		vbtSymbols.add("??_8J5@@7BGG2@@@");
		preparer32.addIntegers(new int[] { 0, -4 });
		preparer64.addIntegers(new int[] { 0, -8 });

		vbtSymbols.add("??_8J5@@7BGG3@@@");
		preparer32.addIntegers(new int[] { 0, -12 });
		preparer64.addIntegers(new int[] { 0, -24 });

		vbtSymbols.add("??_8J6@@7B@");
		preparer32.addIntegers(new int[] { -8, 8, 8, 16, 20 });
		preparer64.addIntegers(new int[] { -8, 16, 16, 32, 40 });

		vbtSymbols.add("??_8J6@@7BGG4@@@");
		preparer32.addIntegers(new int[] { 0, 0 });
		preparer64.addIntegers(new int[] { 0, 0 });

		vbtSymbols.add("??_8J6@@7BGG3@@@");
		preparer32.addIntegers(new int[] { 0, -4 });
		preparer64.addIntegers(new int[] { 0, -8 });

		preparer32.finalizeMemory();
		preparer64.finalizeMemory();

		memory32 = preparer32.getMemory();
		memory64 = preparer64.getMemory();

		MyStubFunctionManager functionManager32 = new MyStubFunctionManager();
		MyStubFunctionManager functionManager64 = new MyStubFunctionManager();

		program32 = new MyStubProgram(memory32, functionManager32);
		program64 = new MyStubProgram(memory64, functionManager64);

		List<Address> addresses32 = preparer32.getAddresses();
		List<Address> addresses64 = preparer64.getAddresses();

		addressByMangledName32 = new HashMap<>();
		addressByMangledName64 = new HashMap<>();

		if (vbtSymbols.size() != addresses32.size() || vbtSymbols.size() != addresses64.size()) {
			throw new AssertException("Fatal: list sizes do not match");
		}
		for (int index = 0; index < vbtSymbols.size(); index++) {
			addressByMangledName32.put(vbtSymbols.get(index), addresses32.get(index));
			addressByMangledName64.put(vbtSymbols.get(index), addresses64.get(index));
		}
	}

	private static String convertCommentsToSpeculative(String original) {
		return original.replace("Virtual Base", "Virtual Base - Speculative Placement");
	}

	private static CppCompositeType createStruct32(String name, int size) {
		Composite composite = new StructureDataType(CategoryPath.ROOT, name, 0, dtm32);
		SymbolPath symbolPath = new SymbolPath(name);
		String mangledName = createMangledName(name, ClassKey.STRUCT);
		return CppCompositeType.createCppStructType(CategoryPath.ROOT, symbolPath, composite, name,
			mangledName, size);
	}

	private static CppCompositeType createStruct64(String name, int size) {
		Composite composite = new StructureDataType(CategoryPath.ROOT, name, 0, dtm64);
		SymbolPath symbolPath = new SymbolPath(name);
		String mangledName = createMangledName(name, ClassKey.STRUCT);
		return CppCompositeType.createCppStructType(CategoryPath.ROOT, symbolPath, composite, name,
			mangledName, 0);
	}

	private static String createMangledName(String className, ClassKey key) {
		StringBuilder builder = new StringBuilder();
		builder.append(".?A");
		switch (key) {
			case UNION:
				builder.append('T');
				break;
			case STRUCT:
				builder.append('U');
				break;
			case CLASS:
				builder.append('V');
				break;
			default:
				String msg = "Cannot handle type during testing" + key;
				Msg.error(null, msg);
				throw new AssertException(msg);
		}
		builder.append(className);
		builder.append("@@");
		return builder.toString();
	}

	private final static DataType u1 = Undefined1DataType.dataType;
	//private final static DataType u2 = Undefined2DataType.dataType;
	private final static DataType u4 = Undefined4DataType.dataType;
	//private final static DataType u8 = Undefined8DataType.dataType;

	//==============================================================================================
	private static class MyTestDummyDataTypeManager extends TestDummyDataTypeManager {
		HashMap<String, DataType> dataTypeMap = new HashMap<>();
		DataOrganizationImpl dataOrg;

		private MyTestDummyDataTypeManager(DataOrganizationImpl dataOrg) {
			this.dataOrg = dataOrg;
		}

		/**
		 * This is not part of the DataTypeManager API... it is only for testing when needing
		 *  to clear results because of another run that creates the same-named types
		 */
		private void clearMap() {
			dataTypeMap = new HashMap<>();
		}

		@Override
		public DataOrganization getDataOrganization() {
			return dataOrg;
		}

		@Override
		public DataType resolve(DataType dataType, DataTypeConflictHandler handler) {
			if (dataType instanceof Composite composite) {
				String name = composite.getName();
				for (DataTypeComponent component : composite.getComponents()) {
					if (component.getDataType() instanceof Structure struct) {
						// TODO:
						// Need to fix the "!internal" to reference static value put into
						//  ClassType helper class
						if (struct.getCategoryPath().getName().equals("!internal") &&
							struct.getName().equals(name)) {
							addDataType(struct, null);
						}
					}
				}
			}
			return addDataType(dataType, null);
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
			return getDataType(new DataTypePath(path, name).getPath());
		}

		@Override
		public DataType getDataType(String dataTypePath) {
			return dataTypeMap.get(dataTypePath);
		}

	}

	//==============================================================================================
	/*
	 * struct A {
	 *    char c;
	 *    int i;
	 * };
	 */
	static CppCompositeType createA_syntactic_struct32(VxtManager vxtManager) {
		CppCompositeType A_struct = createStruct32("A", 0);
		A_struct.addMember("c", u1, false, 0);
		A_struct.addMember("i", u4, false, 0);
		return A_struct;
	}

	static CppCompositeType createA_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createA_struct64(vxtManager) : createA_struct32(vxtManager);
	}

	static CppCompositeType createA_struct32(VxtManager vxtManager) {
		CppCompositeType A_struct = createStruct32("A", 8);
		A_struct.addMember("c", u1, false, 0);
		A_struct.addMember("i", u4, false, 4);
		return A_struct;
	}

	static CppCompositeType createA_struct64(VxtManager vxtManager) {
		CppCompositeType A_struct = createStruct64("A", 8);
		A_struct.addMember("c", u1, false, 0);
		A_struct.addMember("i", u4, false, 4);
		return A_struct;
	}

	//@formatter:off
	/*
	struct A {
	  char c;
	  int i;
	};

	class A	size(8):
		+---
	 0	| c
	  	| <alignment member> (size=3)
	 4	| i
		+---
	 */
	//@formatter:on
	private String getExpectedA_32() {
		String expected =
		//@formatter:off
			"""
			/A
			pack()
			Structure A {
			   0   undefined1   1   c   ""
			   4   undefined4   4   i   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedA_32() {
		return convertCommentsToSpeculative(getExpectedA_32());
	}

	//@formatter:off
	/*
	struct A {
	  char c;
	  int i;
	};

	class A	size(8):
		+---
	 0	| c
	  	| <alignment member> (size=3)
	 4	| i
		+---
	 */
	//@formatter:on
	private String getExpectedA_64() {
		String expected =
		//@formatter:off
			"""
			/A
			pack()
			Structure A {
			   0   undefined1   1   c   ""
			   4   undefined4   4   i   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedA_64() {
		return convertCommentsToSpeculative(getExpectedA_64());
	}

	//==============================================================================================
	/*
	 * struct C {
	 *    int c1;
	 *    void cf();
	 * };
	 */
	static CppCompositeType createC_syntactic_struct32(VxtManager vxtManager) {
		CppCompositeType C_struct = createStruct32("C", 0);
		C_struct.addMember("c1", u4, false, 0);
		return C_struct;
	}

	static CppCompositeType createC_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createC_struct64(vxtManager) : createC_struct32(vxtManager);
	}

	static CppCompositeType createC_struct32(VxtManager vxtManager) {
		CppCompositeType C_struct = createStruct32("C", 4);
		C_struct.addMember("c1", u4, false, 0);
		return C_struct;
	}

	static CppCompositeType createC_struct64(VxtManager vxtManager) {
		CppCompositeType C_struct = createStruct64("C", 4);
		C_struct.addMember("c1", u4, false, 0);
		return C_struct;
	}

	//@formatter:off
	/*
	struct C {
	  int c1;
	  void cf();
	};

	class C	size(4):
		+---
	 0	| c1
		+---
	 */
	//@formatter:on
	private String getExpectedC_32() {
		String expected =
		//@formatter:off
			"""
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedC_32() {
		return convertCommentsToSpeculative(getExpectedC_32());
	}

	//@formatter:off
	/*
	struct C {
	  int c1;
	  void cf();
	};

	class C	size(4):
		+---
	 0	| c1
		+---
	 */
	//@formatter:on
	//@formatter:on
	private String getExpectedC_64() {
		String expected =
		//@formatter:off
			"""
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedC_64() {
		return convertCommentsToSpeculative(getExpectedC_64());
	}

	//==============================================================================================
	/*
	 * struct CC1 {
	 *    int cc11;
	 *    void cc1f();
	 * };
	 */
	static CppCompositeType createCC1_syntactic_struct32(VxtManager vxtManager) {
		CppCompositeType CC1_struct = createStruct32("CC1", 0);
		CC1_struct.addMember("cc11", u4, false, 0);
		return CC1_struct;
	}

	static CppCompositeType createCC1_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createCC1_struct64(vxtManager) : createCC1_struct32(vxtManager);
	}

	static CppCompositeType createCC1_struct32(VxtManager vxtManager) {
		CppCompositeType CC1_struct = createStruct32("CC1", 4);
		CC1_struct.addMember("cc11", u4, false, 0);
		return CC1_struct;
	}

	static CppCompositeType createCC1_struct64(VxtManager vxtManager) {
		CppCompositeType CC1_struct = createStruct64("CC1", 4);
		CC1_struct.addMember("cc11", u4, false, 0);
		return CC1_struct;
	}

	//@formatter:off
	/*
	struct CC1 {
	  int cc11;
	  void cc1f();
	};

	class CC1	size(4):
		+---
 	0	| cc11
		+---
	 */
	//@formatter:on
	private String getExpectedCC1_32() {
		String expected =
		//@formatter:off
			"""
			/CC1
			pack()
			Structure CC1 {
			   0   undefined4   4   cc11   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC1_32() {
		return convertCommentsToSpeculative(getExpectedCC1_32());
	}

	//@formatter:off
	/*
	struct CC1 {
	  int cc11;
	  void cc1f();
	};

	class CC1	size(4):
		+---
 	0	| cc11
		+---
	 */
	//@formatter:on
	private String getExpectedCC1_64() {
		String expected =
		//@formatter:off
			"""
			/CC1
			pack()
			Structure CC1 {
			   0   undefined4   4   cc11   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC1_64() {
		return convertCommentsToSpeculative(getExpectedCC1_64());
	}

	//==============================================================================================
	/*
	 * struct CC2 {
	 *    int cc21;
	 *    void cc2f();
	 * };
	 */
	static CppCompositeType createCC2_syntactic_struct32(VxtManager vxtManager) {
		CppCompositeType CC2_struct = createStruct32("CC2", 0);
		CC2_struct.addMember("cc21", u4, false, 0);
		return CC2_struct;
	}

	static CppCompositeType createCC2_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createCC2_struct64(vxtManager) : createCC2_struct32(vxtManager);
	}

	static CppCompositeType createCC2_struct32(VxtManager vxtManager) {
		CppCompositeType CC2_struct = createStruct32("CC2", 4);
		CC2_struct.addMember("cc21", u4, false, 0);
		return CC2_struct;
	}

	static CppCompositeType createCC2_struct64(VxtManager vxtManager) {
		CppCompositeType CC2_struct = createStruct64("CC2", 4);
		CC2_struct.addMember("cc21", u4, false, 0);
		return CC2_struct;
	}

	//@formatter:off
	/*
	struct CC2 {
	  int cc21;
	  void cc2f();
	};

	class CC2	size(4):
		+---
	 0	| cc21
		+---
	 */
	//@formatter:on
	private String getExpectedCC2_32() {
		String expected =
		//@formatter:off
			"""
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC2_32() {
		return convertCommentsToSpeculative(getExpectedCC2_32());
	}

	//@formatter:off
	/*
	struct CC2 {
	  int cc21;
	  void cc2f();
	};

	class CC2	size(4):
		+---
	 0	| cc21
		+---
	 */
	//@formatter:on
	private String getExpectedCC2_64() {
		String expected =
		//@formatter:off
			"""
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC2_64() {
		return convertCommentsToSpeculative(getExpectedCC2_64());
	}

	//==============================================================================================
	/*
	 * struct CC3 {
	 *    void cc3f();
	 * };
	 */
	static CppCompositeType createCC3_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createCC3_struct64(vxtManager) : createCC3_struct32(vxtManager);
	}

	static CppCompositeType createCC3_struct32(VxtManager vxtManager) {
		CppCompositeType CC3_struct = createStruct32("CC3", 0); //TODO size 1 or 0?
		return CC3_struct;
	}

	static CppCompositeType createCC3_struct64(VxtManager vxtManager) {
		CppCompositeType CC3_struct = createStruct64("CC3", 0); //TODO size 1 or 0?
		return CC3_struct;
	}

	//@formatter:off
	/*
	struct CC3 {
	  void cc3f();
	};

	class CC3	size(1):
		+---
		+---
	 */
	//@formatter:on
	private String getExpectedCC3_32() {
		String expected =
		//@formatter:off
			"""
			/CC3
			pack(disabled)
			Structure CC3 {
			}
			Length: 0 Alignment: 1""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC3_32() {
		return convertCommentsToSpeculative(getExpectedCC3_32());
	}

	//@formatter:off
	/*
	struct CC3 {
	  void cc3f();
	};

	class CC3	size(1):
		+---
		+---
	 */
	//@formatter:on
	private String getExpectedCC3_64() {
		String expected =
		//@formatter:off
			"""
			/CC3
			pack(disabled)
			Structure CC3 {
			}
			Length: 0 Alignment: 1""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC3_64() {
		return convertCommentsToSpeculative(getExpectedCC3_64());
	}

	//==============================================================================================
	/*
	 * struct D : C {
	 *    int d1;
	 *    void df();
	 * };
	 */
	static CppCompositeType createD_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType C_struct) {
		return is64Bit ? createD_struct64(vxtManager, C_struct)
				: createD_struct32(vxtManager, C_struct);
	}

	static CppCompositeType createD_struct32(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType D_struct = createStruct32("D", 8);
			D_struct.addDirectBaseClass(C_struct, 0);
			D_struct.addMember("d1", u4, false, 4);
			return D_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createD_struct64(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType D_struct = createStruct64("D", 8);
			D_struct.addDirectBaseClass(C_struct, 0);
			D_struct.addMember("d1", u4, false, 4);
			return D_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct D : C {
	  int d1;
	  void df();
	};

	class D	size(8):
		+---
	 0	| +--- (base class C)
	 0	| | c1
		| +---
	 4	| d1
		+---
	 */
	//@formatter:on
	private String getExpectedD_32() {
		String expected =
		//@formatter:off
			"""
			/D
			pack()
			Structure D {
			   0   C   4      "Base"
			   4   undefined4   4   d1   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedD_32() {
		return convertCommentsToSpeculative(getExpectedD_32());
	}

	//@formatter:off
	/*
	struct D : C {
	  int d1;
	  void df();
	};

	class D	size(8):
		+---
	 0	| +--- (base class C)
	 0	| | c1
		| +---
	 4	| d1
		+---
	 */
	//@formatter:on
	private String getExpectedD_64() {
		String expected =
		//@formatter:off
			"""
			/D
			pack()
			Structure D {
			   0   C   4      "Base"
			   4   undefined4   4   d1   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedD_64() {
		return convertCommentsToSpeculative(getExpectedD_64());
	}

	//==============================================================================================
	/*
	 * struct E {
	 *	  int e1;
	 *	  void ef();
	 *	};
	 */
	static CppCompositeType createE_syntactic_struct32(VxtManager vxtManager) {
		CppCompositeType E_struct = createStruct32("E", 0);
		E_struct.addMember("e1", u4, false, 0);
		return E_struct;
	}

	static CppCompositeType createE_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createE_struct64(vxtManager) : createE_struct32(vxtManager);
	}

	static CppCompositeType createE_struct32(VxtManager vxtManager) {
		CppCompositeType E_struct = createStruct32("E", 4);
		E_struct.addMember("e1", u4, false, 0);
		return E_struct;
	}

	static CppCompositeType createE_struct64(VxtManager vxtManager) {
		CppCompositeType E_struct = createStruct64("E", 4);
		E_struct.addMember("e1", u4, false, 0);
		return E_struct;
	}

	//@formatter:off
	/*
	struct E {
	  int e1;
	  void ef();
	};

	class E	size(4):
		+---
	 0	| e1
		+---
	 */
	//@formatter:on
	private String getExpectedE_32() {
		String expected =
		//@formatter:off
			"""
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedE_32() {
		return convertCommentsToSpeculative(getExpectedE_32());
	}

	//@formatter:off
	/*
	struct E {
	  int e1;
	  void ef();
	};

	class E	size(4):
		+---
	 0	| e1
		+---
	 */
	//@formatter:on
	private String getExpectedE_64() {
		String expected =
		//@formatter:off
			"""
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedE_64() {
		return convertCommentsToSpeculative(getExpectedE_64());
	}

	//==============================================================================================
	/*
	 * struct F : C, E {
	 *	  int f1;
	 *	  void ff();
	 *	};
	 */
	static CppCompositeType createF_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType C_struct, CppCompositeType E_struct) {
		return is64Bit ? createF_struct64(vxtManager, C_struct, E_struct)
				: createF_struct32(vxtManager, C_struct, E_struct);
	}

	static CppCompositeType createF_struct32(VxtManager vxtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType F_struct = createStruct32("F", 12);
			F_struct.addDirectBaseClass(C_struct, 0);
			F_struct.addDirectBaseClass(E_struct, 4);
			F_struct.addMember("f1", u4, false, 8);
			return F_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createF_struct64(VxtManager vxtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType F_struct = createStruct64("F", 12);
			F_struct.addDirectBaseClass(C_struct, 0);
			F_struct.addDirectBaseClass(E_struct, 4);
			F_struct.addMember("f1", u4, false, 8);
			return F_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct F : C, E {
	  int f1;
	  void ff();
	};

	class F	size(12):
		+---
	 0	| +--- (base class C)
	 0	| | c1
		| +---
	 4	| +--- (base class E)
	 4	| | e1
		| +---
	 8	| f1
		+---
	 */
	//@formatter:on
	private String getExpectedF_32() {
		String expected =
		//@formatter:off
			"""
			/F
			pack()
			Structure F {
			   0   C   4      "Base"
			   4   E   4      "Base"
			   8   undefined4   4   f1   ""
			}
			Length: 12 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedF_32() {
		return convertCommentsToSpeculative(getExpectedF_32());
	}

	//@formatter:off
	/*
	struct F : C, E {
	  int f1;
	  void ff();
	};

	class F	size(12):
		+---
	 0	| +--- (base class C)
	 0	| | c1
		| +---
	 4	| +--- (base class E)
	 4	| | e1
		| +---
	 8	| f1
		+---
	 */
	//@formatter:on
	private String getExpectedF_64() {
		String expected =
		//@formatter:off
			"""
			/F
			pack()
			Structure F {
			   0   C   4      "Base"
			   4   E   4      "Base"
			   8   undefined4   4   f1   ""
			}
			Length: 12 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedF_64() {
		return convertCommentsToSpeculative(getExpectedF_64());
	}

	//==============================================================================================
	/*
	 * struct G : virtual C {
	 *	  int g1;
	 *	  void gf();
	 *	};
	 */
	static CppCompositeType createG_syntactic_struct32(VxtManager vxtManager) {
		return createG_syntactic_struct32(vxtManager, null);
	}

	static CppCompositeType createG_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType C_struct) {
		CppCompositeType G_struct = createStruct32("G", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			G_struct.addVirtualSyntacticBaseClass(C_struct);
			G_struct.addMember("g1", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return G_struct;
	}

	static CppCompositeType createG_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType C_struct) {
		return is64Bit ? createG_struct64(vxtManager, C_struct)
				: createG_struct32(vxtManager, C_struct);
	}

	static CppCompositeType createG_struct32(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType G_struct = createStruct32("G", 12);
			G_struct.addDirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			G_struct.addMember("g1", u4, false, 4);
			return G_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createG_struct64(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType G_struct = createStruct64("G", 20);
			G_struct.addDirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			G_struct.addMember("g1", u4, false, 8);
			return G_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct G : virtual C {
	  int g1;
	  void gf();
	};

	class G	size(12):
		+---
	 0	| {vbptr}
	 4	| g1
		+---
		+--- (virtual base C)
	 8	| c1
		+---

	G::$vbtable@:
	 0	| 0
	 1	| 8 (Gd(G+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C       8       0       4 0
	 */
	//@formatter:on
	private String getExpectedG_32() {
		String expected =
		//@formatter:off
			"""
			/G
			pack()
			Structure G {
			   0   G   8      "Self Base"
			   8   C   4      "Virtual Base"
			}
			Length: 12 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g1   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedG_32() {
		return convertCommentsToSpeculative(getExpectedG_32());
	}

	//@formatter:off
	/*
	struct G : virtual C {
	  int g1;
	  void gf();
	};

	class G	size(20):
		+---
	 0	| {vbptr}
	 8	| g1
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	16	| c1
		+---

	G::$vbtable@:
	 0	| 0
	 1	| 16 (Gd(G+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      16       0       4 0
	 */
	//@formatter:on
	private String getExpectedG_64() {
		String expected =
		//@formatter:off
			"""
			/G
			pack()
			Structure G {
			   0   G   16      "Self Base"
			   16   C   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedG_64() {
		return convertCommentsToSpeculative(getExpectedG_64());
	}

	//==============================================================================================
	/*
	 * struct H : virtual C {
	 *	  int h1;
	 *	  void hf();
	 *	};
	 */
	static CppCompositeType createH_syntactic_struct32(VxtManager vxtManager) {
		return createH_syntactic_struct32(vxtManager, null);
	}

	static CppCompositeType createH_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType C_struct) {
		CppCompositeType H_struct = createStruct32("H", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			H_struct.addVirtualSyntacticBaseClass(C_struct);
			H_struct.addMember("h1", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return H_struct;
	}

	static CppCompositeType createH_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType C_struct) {
		return is64Bit ? createH_struct64(vxtManager, C_struct)
				: createH_struct32(vxtManager, C_struct);
	}

	static CppCompositeType createH_struct32(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType H_struct = createStruct32("H", 12);
			H_struct.addDirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			H_struct.addMember("h1", u4, false, 4);
			return H_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createH_struct64(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType H_struct = createStruct64("H", 20);
			H_struct.addDirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			H_struct.addMember("h1", u4, false, 8);
			return H_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct H : virtual C {
	  int h1;
	  void hf();
	};

	class H	size(12):
		+---
	 0	| {vbptr}
	 4	| h1
		+---
		+--- (virtual base C)
	 8	| c1
		+---

	H::$vbtable@:
	 0	| 0
	 1	| 8 (Hd(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C       8       0       4 0
	 */
	//@formatter:on
	private String getExpectedH_32() {
		String expected =
		//@formatter:off
			"""
			/H
			pack()
			Structure H {
			   0   H   8      "Self Base"
			   8   C   4      "Virtual Base"
			}
			Length: 12 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h1   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedH_32() {
		return convertCommentsToSpeculative(getExpectedH_32());
	}

	//@formatter:off
	/*
	struct H : virtual C {
	  int h1;
	  void hf();
	};

	class H	size(20):
		+---
	 0	| {vbptr}
	 8	| h1
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	16	| c1
		+---

	H::$vbtable@:
	 0	| 0
	 1	| 16 (Hd(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      16       0       4 0
	 */
	//@formatter:on
	private String getExpectedH_64() {
		String expected =
		//@formatter:off
			"""
			/H
			pack()
			Structure H {
			   0   H   16      "Self Base"
			   16   C   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedH_64() {
		return convertCommentsToSpeculative(getExpectedH_64());
	}

	//==============================================================================================
	/*
	 * struct G1 : virtual C, virtual E {
	 *	  int g11;
	 *	  void g1f();
	 *	};
	 */
	static CppCompositeType createG1_syntactic_struct32(VxtManager vxtManager) {
		return createG1_syntactic_struct32(vxtManager, null, null);
	}

	static CppCompositeType createG1_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType C_struct, CppCompositeType E_struct) {
		CppCompositeType G1_struct = createStruct32("G1", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vxtManager);
			}
			G1_struct.addVirtualSyntacticBaseClass(C_struct);
			G1_struct.addVirtualSyntacticBaseClass(E_struct);
			G1_struct.addMember("g11", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return G1_struct;
	}

	static CppCompositeType createG1_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType C_struct, CppCompositeType E_struct) {
		return is64Bit ? createG1_struct64(vxtManager, C_struct, E_struct)
				: createG1_struct32(vxtManager, C_struct, E_struct);
	}

	static CppCompositeType createG1_struct32(VxtManager vxtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType G1_struct = createStruct32("G1", 16);
			G1_struct.addDirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			G1_struct.addDirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			G1_struct.addMember("g11", u4, false, 4);
			return G1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createG1_struct64(VxtManager vxtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType G1_struct = createStruct64("G1", 24);
			G1_struct.addDirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			G1_struct.addDirectVirtualBaseClass(E_struct, 0, vbtptr64, 2);
			G1_struct.addMember("g11", u4, false, 8);
			return G1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct G1 : virtual C, virtual E {
	  int g11;
	  void g1f();
	};

	class G1	size(16):
		+---
	 0	| {vbptr}
	 4	| g11
		+---
		+--- (virtual base C)
	 8	| c1
		+---
		+--- (virtual base E)
	12	| e1
		+---

	G1::$vbtable@:
	 0	| 0
	 1	| 8 (G1d(G1+0)C)
	 2	| 12 (G1d(G1+0)E)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C       8       0       4 0
	               E      12       0       8 0
	 */
	//@formatter:on
	private String getExpectedG1_32() {
		String expected =
		//@formatter:off
			"""
			/G1
			pack()
			Structure G1 {
			   0   G1   8      "Self Base"
			   8   C   4      "Virtual Base"
			   12   E   4      "Virtual Base"
			}
			Length: 16 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedG1_32() {
		return convertCommentsToSpeculative(getExpectedG1_32());
	}

	//@formatter:off
	/*
	struct G1 : virtual C, virtual E {
	  int g11;
	  void g1f();
	};

	class G1	size(24):
		+---
	 0	| {vbptr}
	 8	| g11
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	16	| c1
		+---
		+--- (virtual base E)
	20	| e1
		+---

	G1::$vbtable@:
	 0	| 0
	 1	| 16 (G1d(G1+0)C)
	 2	| 20 (G1d(G1+0)E)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      16       0       4 0
	               E      20       0       8 0
	 */
	//@formatter:on
	private String getExpectedG1_64() {
		String expected =
		//@formatter:off
			"""
			/G1
			pack()
			Structure G1 {
			   0   G1   16      "Self Base"
			   16   C   4      "Virtual Base"
			   20   E   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedG1_64() {
		return convertCommentsToSpeculative(getExpectedG1_64());
	}

	//==============================================================================================
	/*
	 * struct H1 : virtual E, virtual C { //order reversed from G1
	 *	  int h11;
	 *	  void h1f();
	 *	};
	 */
	static CppCompositeType createH1_syntactic_struct32(VxtManager vxtManager) {
		return createH1_syntactic_struct32(vxtManager, null, null);
	}

	static CppCompositeType createH1_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType H1_struct = createStruct32("H1", 0);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vxtManager);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			H1_struct.addVirtualSyntacticBaseClass(E_struct);
			H1_struct.addVirtualSyntacticBaseClass(C_struct);
			H1_struct.addMember("h11", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return H1_struct;
	}

	static CppCompositeType createH1_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		return is64Bit ? createH1_struct64(vxtManager, E_struct, C_struct)
				: createH1_struct32(vxtManager, E_struct, C_struct);
	}

	static CppCompositeType createH1_struct32(VxtManager vxtManager, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		try {
			CppCompositeType H1_struct = createStruct32("H1", 16);
			H1_struct.addDirectVirtualBaseClass(E_struct, 0, vbtptr32, 1);
			H1_struct.addDirectVirtualBaseClass(C_struct, 0, vbtptr32, 2);
			H1_struct.addMember("h11", u4, false, 4);
			return H1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createH1_struct64(VxtManager vxtManager, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		try {
			CppCompositeType H1_struct = createStruct64("H1", 24);
			H1_struct.addDirectVirtualBaseClass(E_struct, 0, vbtptr64, 1);
			H1_struct.addDirectVirtualBaseClass(C_struct, 0, vbtptr64, 2);
			H1_struct.addMember("h11", u4, false, 8);
			return H1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct H1 : virtual E, virtual C { //order reversed from G1
	  int h11;
	  void h1f();
	};

	class H1	size(16):
		+---
	 0	| {vbptr}
	 4	| h11
		+---
		+--- (virtual base E)
	 8	| e1
		+---
		+--- (virtual base C)
	12	| c1
		+---

	H1::$vbtable@:
	 0	| 0
	 1	| 8 (H1d(H1+0)E)
	 2	| 12 (H1d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               E       8       0       4 0
	               C      12       0       8 0
	 */
	//@formatter:on
	private String getExpectedH1_32() {
		String expected =
		//@formatter:off
			"""
			/H1
			pack()
			Structure H1 {
			   0   H1   8      "Self Base"
			   8   E   4      "Virtual Base"
			   12   C   4      "Virtual Base"
			}
			Length: 16 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h11   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedH1_32() {
		return convertCommentsToSpeculative(getExpectedH1_32());
	}

	//@formatter:off
	/*
	struct H1 : virtual E, virtual C { //order reversed from G1
	  int h11;
	  void h1f();
	};

	class H1	size(24):
		+---
	 0	| {vbptr}
	 8	| h11
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base E)
	16	| e1
		+---
		+--- (virtual base C)
	20	| c1
		+---

	H1::$vbtable@:
	 0	| 0
	 1	| 16 (H1d(H1+0)E)
	 2	| 20 (H1d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               E      16       0       4 0
	               C      20       0       8 0
	 */
	//@formatter:on
	private String getExpectedH1_64() {
		String expected =
		//@formatter:off
			"""
			/H1
			pack()
			Structure H1 {
			   0   H1   16      "Self Base"
			   16   E   4      "Virtual Base"
			   20   C   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h11   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedH1_64() {
		return convertCommentsToSpeculative(getExpectedH1_64());
	}

	//==============================================================================================
	/*
	 * struct GG1 : virtual CC1 {
	 *	  int gg11;
	 *	  void gg1f();
	 *	};
	 */
	static CppCompositeType createGG1_syntactic_struct32(VxtManager vxtManager) {
		return createGG1_syntactic_struct32(vxtManager, null);
	}

	static CppCompositeType createGG1_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType CC1_struct) {
		CppCompositeType GG1_struct = createStruct32("GG1", 0);
		try {
			if (CC1_struct == null) {
				CC1_struct = createCC1_struct32(vxtManager);
			}
			GG1_struct.addVirtualSyntacticBaseClass(CC1_struct);
			GG1_struct.addMember("gg11", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG1_struct;
	}

	static CppCompositeType createGG1_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType CC1_struct) {
		return is64Bit ? createGG1_struct64(vxtManager, CC1_struct)
				: createGG1_struct32(vxtManager, CC1_struct);
	}

	static CppCompositeType createGG1_struct32(VxtManager vxtManager, CppCompositeType CC1_struct) {
		try {
			CppCompositeType GG1_struct = createStruct32("GG1", 12);
			GG1_struct.addDirectVirtualBaseClass(CC1_struct, 0, vbtptr32, 1);
			GG1_struct.addMember("gg11", u4, false, 4);
			return GG1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createGG1_struct64(VxtManager vxtManager, CppCompositeType CC1_struct) {
		try {
			CppCompositeType GG1_struct = createStruct64("GG1", 20);
			GG1_struct.addDirectVirtualBaseClass(CC1_struct, 0, vbtptr64, 1);
			GG1_struct.addMember("gg11", u4, false, 8);
			return GG1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct GG1 : virtual CC1 {
	  int gg11;
	  void gg1f();
	};

	class GG1	size(12):
		+---
	 0	| {vbptr}
	 4	| gg11
		+---
		+--- (virtual base CC1)
	 8	| cc11
		+---

	GG1::$vbtable@:
	 0	| 0
	 1	| 8 (GG1d(GG1+0)CC1)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC1       8       0       4 0
	 */
	//@formatter:on
	private String getExpectedGG1_32() {
		String expected =
		//@formatter:off
			"""
			/GG1
			pack()
			Structure GG1 {
			   0   GG1   8      "Self Base"
			   8   CC1   4      "Virtual Base"
			}
			Length: 12 Alignment: 4
			/CC1
			pack()
			Structure CC1 {
			   0   undefined4   4   cc11   ""
			}
			Length: 4 Alignment: 4
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg11   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG1_32() {
		return convertCommentsToSpeculative(getExpectedGG1_32());
	}

	//@formatter:off
	/*
	struct GG1 : virtual CC1 {
	  int gg11;
	  void gg1f();
	};

	class GG1	size(20):
		+---
	 0	| {vbptr}
	 8	| gg11
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC1)
	16	| cc11
		+---

	GG1::$vbtable@:
	 0	| 0
	 1	| 16 (GG1d(GG1+0)CC1)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC1      16       0       4 0
	 */
	//@formatter:on
	private String getExpectedGG1_64() {
		String expected =
		//@formatter:off
			"""
			/GG1
			pack()
			Structure GG1 {
			   0   GG1   16      "Self Base"
			   16   CC1   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/CC1
			pack()
			Structure CC1 {
			   0   undefined4   4   cc11   ""
			}
			Length: 4 Alignment: 4
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg11   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG1_64() {
		return convertCommentsToSpeculative(getExpectedGG1_64());
	}

	//==============================================================================================
	/*
	 * struct GG2 : virtual CC2 {
	 *	  int gg21;
	 *	  void gg2f();
	 *	};
	 */
	static CppCompositeType createGG2_syntactic_struct32(VxtManager vxtManager) {
		return createGG2_syntactic_struct32(vxtManager, null);
	}

	static CppCompositeType createGG2_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType CC2_struct) {
		CppCompositeType GG2_struct = createStruct32("GG2", 0);
		try {
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vxtManager);
			}
			GG2_struct.addVirtualSyntacticBaseClass(CC2_struct);
			GG2_struct.addMember("gg21", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG2_struct;
	}

	static CppCompositeType createGG2_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType CC2_struct) {
		return is64Bit ? createGG2_struct64(vxtManager, CC2_struct)
				: createGG2_struct32(vxtManager, CC2_struct);
	}

	static CppCompositeType createGG2_struct32(VxtManager vxtManager, CppCompositeType CC2_struct) {
		try {
			CppCompositeType GG2_struct = createStruct32("GG2", 12);
			GG2_struct.addDirectVirtualBaseClass(CC2_struct, 0, vbtptr32, 1);
			GG2_struct.addMember("gg21", u4, false, 4);
			return GG2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createGG2_struct64(VxtManager vxtManager, CppCompositeType CC2_struct) {
		try {
			CppCompositeType GG2_struct = createStruct64("GG2", 20);
			GG2_struct.addDirectVirtualBaseClass(CC2_struct, 0, vbtptr64, 1);
			GG2_struct.addMember("gg21", u4, false, 8);
			return GG2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct GG2 : virtual CC2 {
	  int gg21;
	  void gg2f();
	};

	class GG2	size(12):
		+---
	 0	| {vbptr}
	 4	| gg21
		+---
		+--- (virtual base CC2)
	 8	| cc21
		+---

	GG2::$vbtable@:
	 0	| 0
	 1	| 8 (GG2d(GG2+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC2       8       0       4 0
	 */
	//@formatter:on
	private String getExpectedGG2_32() {
		String expected =
		//@formatter:off
			"""
			/GG2
			pack()
			Structure GG2 {
			   0   GG2   8      "Self Base"
			   8   CC2   4      "Virtual Base"
			}
			Length: 12 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg21   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG2_32() {
		return convertCommentsToSpeculative(getExpectedGG2_32());
	}

	//@formatter:off
	/*
	struct GG2 : virtual CC2 {
	  int gg21;
	  void gg2f();
	};

	class GG2	size(20):
		+---
	 0	| {vbptr}
	 8	| gg21
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC2)
	16	| cc21
		+---

	GG2::$vbtable@:
	 0	| 0
	 1	| 16 (GG2d(GG2+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC2      16       0       4 0
	 */
	//@formatter:on
	private String getExpectedGG2_64() {
		String expected =
		//@formatter:off
			"""
			/GG2
			pack()
			Structure GG2 {
			   0   GG2   16      "Self Base"
			   16   CC2   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg21   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG2_64() {
		return convertCommentsToSpeculative(getExpectedGG2_64());
	}

	//==============================================================================================
	/*
	 * struct GG3 : virtual CC2 {
	 *	  int gg31;
	 *	  void gg3f();
	 *	};
	 */
	static CppCompositeType createGG3_syntactic_struct32(VxtManager vxtManager) {
		return createGG3_syntactic_struct32(vxtManager, null);
	}

	static CppCompositeType createGG3_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType CC2_struct) {
		CppCompositeType GG3_struct = createStruct32("GG3", 0);
		try {
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vxtManager);
			}
			GG3_struct.addVirtualSyntacticBaseClass(CC2_struct);
			GG3_struct.addMember("gg31", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG3_struct;
	}

	static CppCompositeType createGG3_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType CC2_struct) {
		return is64Bit ? createGG3_struct64(vxtManager, CC2_struct)
				: createGG3_struct32(vxtManager, CC2_struct);
	}

	static CppCompositeType createGG3_struct32(VxtManager vxtManager, CppCompositeType CC2_struct) {
		try {
			CppCompositeType GG3_struct = createStruct32("GG3", 12);
			GG3_struct.addDirectVirtualBaseClass(CC2_struct, 0, vbtptr32, 1);
			GG3_struct.addMember("gg31", u4, false, 4);
			return GG3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createGG3_struct64(VxtManager vxtManager, CppCompositeType CC2_struct) {
		try {
			CppCompositeType GG3_struct = createStruct64("GG3", 20);
			GG3_struct.addDirectVirtualBaseClass(CC2_struct, 0, vbtptr64, 1);
			GG3_struct.addMember("gg31", u4, false, 8);
			return GG3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct GG3 : virtual CC2 {
	  int gg31;
	  void gg3f();
	};

	class GG3	size(12):
		+---
	 0	| {vbptr}
	 4	| gg31
		+---
		+--- (virtual base CC2)
	 8	| cc21
		+---

	GG3::$vbtable@:
	 0	| 0
	 1	| 8 (GG3d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC2       8       0       4 0
	 */
	//@formatter:on
	private String getExpectedGG3_32() {
		String expected =
		//@formatter:off
			"""
			/GG3
			pack()
			Structure GG3 {
			   0   GG3   8      "Self Base"
			   8   CC2   4      "Virtual Base"
			}
			Length: 12 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg31   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG3_32() {
		return convertCommentsToSpeculative(getExpectedGG3_32());
	}

	//@formatter:off
	/*
	struct GG3 : virtual CC2 {
	  int gg31;
	  void gg3f();
	};

	class GG3	size(20):
		+---
	 0	| {vbptr}
	 8	| gg31
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC2)
	16	| cc21
		+---

	GG3::$vbtable@:
	 0	| 0
 	1	| 16 (GG3d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC2      16       0       4 0
	 */
	//@formatter:on
	private String getExpectedGG3_64() {
		String expected =
		//@formatter:off
			"""
			/GG3
			pack()
			Structure GG3 {
			   0   GG3   16      "Self Base"
			   16   CC2   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg31   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG3_64() {
		return convertCommentsToSpeculative(getExpectedGG3_64());
	}

	//==============================================================================================
	/*
	 * struct GG4 : virtual CC3 {
	 *	  int gg41;
	 *	  void gg5f();
	 *	};
	 */
	static CppCompositeType createGG4_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType CC3_struct) {
		return is64Bit ? createGG4_struct64(vxtManager, CC3_struct)
				: createGG4_struct32(vxtManager, CC3_struct);
	}

	static CppCompositeType createGG4_struct32(VxtManager vxtManager, CppCompositeType CC3_struct) {
		try {
			CppCompositeType GG4_struct = createStruct32("GG4", 8);
			GG4_struct.addDirectVirtualBaseClass(CC3_struct, 0, vbtptr32, 1);
			GG4_struct.addMember("gg41", u4, false, 4);
			return GG4_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createGG4_struct64(VxtManager vxtManager, CppCompositeType CC3_struct) {
		try {
			CppCompositeType GG4_struct = createStruct64("GG4", 16);
			GG4_struct.addDirectVirtualBaseClass(CC3_struct, 0, vbtptr64, 1);
			GG4_struct.addMember("gg41", u4, false, 8);
			return GG4_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct GG4 : virtual CC3 {
	  int gg41;
	  void gg4f();
	};

	class GG4	size(8):
		+---
	 0	| {vbptr}
	 4	| gg41
		+---
		+--- (virtual base CC3)
		+---

	GG4::$vbtable@:
	 0	| 0
	 1	| 8 (GG4d(GG4+0)CC3)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC3       8       0       4 0
	 */
	//@formatter:on
	// TODO: consider if we want to change the format on the output to provide information
	//  about zero-sized virtual structure components trailing at the end.  We currently let
	//  this information drop on the floor.  So in this case, our output does not show
	//  the fact that CC3 is a zero-sized virtual parent.
	private String getExpectedGG4_32() {
		String expected =
		//@formatter:off
			"""
			/GG4
			pack()
			Structure GG4 {
			   0   GG4   8      "Self Base"
			}
			Length: 8 Alignment: 4
			/GG4/!internal/GG4
			pack()
			Structure GG4 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg41   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG4_32() {
		return convertCommentsToSpeculative(getExpectedGG4_32());
	}

	//@formatter:off
	/*
	struct GG4 : virtual CC3 {
	  int gg41;
	  void gg4f();
	};

	class GG4	size(16):
		+---
	 0	| {vbptr}
	 8	| gg41
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC3)
		+---

	GG4::$vbtable@:
	 0	| 0
	 1	| 16 (GG4d(GG4+0)CC3)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC3      16       0       4 0
	 */
	//@formatter:on
	// TODO: consider if we want to change the format on the output to provide information
	//  about zero-sized virtual structure components trailing at the end.  We currently let
	//  this information drop on the floor.  So in this case, our output does not show
	//  the fact that CC3 is a zero-sized virtual parent.
	private String getExpectedGG4_64() {
		String expected =
		//@formatter:off
			"""
			/GG4
			pack()
			Structure GG4 {
			   0   GG4   16      "Self Base"
			}
			Length: 16 Alignment: 8
			/GG4/!internal/GG4
			pack()
			Structure GG4 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg41   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG4_64() {
		return convertCommentsToSpeculative(getExpectedGG4_64());
	}

	//==============================================================================================
	/*
	 * struct I : G, H {
	 *	  int i1;
	 *	  void _if();
	 *	};
	 */
	static CppCompositeType createI_syntactic_struct32(VxtManager vxtManager) {
		return createI_syntactic_struct32(vxtManager, null, null, null);
	}

	static CppCompositeType createI_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType G_struct, CppCompositeType H_struct, CppCompositeType C_struct) {
		CppCompositeType I_struct = createStruct32("I", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			// Could be problem if only one of G or H is null: won't have same C.
			if (G_struct == null) {
				G_struct = createG_struct32(vxtManager, C_struct);
			}
			if (H_struct == null) {
				H_struct = createH_struct32(vxtManager, C_struct);
			}
			I_struct.addDirectSyntacticBaseClass(G_struct);
			I_struct.addDirectSyntacticBaseClass(H_struct);
			I_struct.addMember("i1", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I_struct;
	}

	static CppCompositeType createI_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G_struct, CppCompositeType H_struct, CppCompositeType C_struct) {
		return is64Bit ? createI_struct64(vxtManager, G_struct, H_struct, C_struct)
				: createI_struct32(vxtManager, G_struct, H_struct, C_struct);
	}

	static CppCompositeType createI_struct32(VxtManager vxtManager, CppCompositeType G_struct,
			CppCompositeType H_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I_struct = createStruct32("I", 24);
			I_struct.addDirectBaseClass(G_struct, 0);
			I_struct.addDirectBaseClass(H_struct, 8);
			I_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			I_struct.addMember("i1", u4, false, 16);
			return I_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI_struct64(VxtManager vxtManager, CppCompositeType G_struct,
			CppCompositeType H_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I_struct = createStruct64("I", 44);
			I_struct.addDirectBaseClass(G_struct, 0);
			I_struct.addDirectBaseClass(H_struct, 16);
			I_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			I_struct.addMember("i1", u4, false, 32);
			return I_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct I : G, H {
	  int i1;
	  void _if();
	};

	class I	size(24):
		+---
	 0	| +--- (base class G)
	 0	| | {vbptr}
	 4	| | g1
		| +---
	 8	| +--- (base class H)
	 8	| | {vbptr}
	12	| | h1
		| +---
	16	| i1
		+---
		+--- (virtual base C)
	20	| c1
		+---

	I::$vbtable@G@:
	 0	| 0
	 1	| 20 (Id(G+0)C)

	I::$vbtable@H@:
	 0	| 0
	 1	| 12 (Id(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      20       0       4 0
	 */
	//@formatter:on
	private String getExpectedI_32() {
		String expected =
		//@formatter:off
			"""
			/I
			pack()
			Structure I {
			   0   I   20      "Self Base"
			   20   C   4      "Virtual Base"
			}
			Length: 24 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g1   ""
			}
			Length: 8 Alignment: 4
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h1   ""
			}
			Length: 8 Alignment: 4
			/I/!internal/I
			pack()
			Structure I {
			   0   G   8      "Base"
			   8   H   8      "Base"
			   16   undefined4   4   i1   ""
			}
			Length: 20 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI_32() {
		return convertCommentsToSpeculative(getExpectedI_32());
	}

	//@formatter:off
	/*
	struct I : G, H {
	  int i1;
	  void _if();
	};

	class I	size(44):
		+---
	 0	| +--- (base class G)
	 0	| | {vbptr}
	 8	| | g1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class H)
	16	| | {vbptr}
	24	| | h1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	32	| i1
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	40	| c1
		+---

	I::$vbtable@G@:
	 0	| 0
 	1	| 40 (Id(G+0)C)

	I::$vbtable@H@:
	 0	| 0
	 1	| 24 (Id(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      40       0       4 0
	 */
	//@formatter:on
	private String getExpectedI_64() {
		String expected =
		//@formatter:off
			"""
			/I
			pack()
			Structure I {
			   0   I   40      "Self Base"
			   40   C   4      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g1   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h1   ""
			}
			Length: 16 Alignment: 8
			/I/!internal/I
			pack()
			Structure I {
			   0   G   16      "Base"
			   16   H   16      "Base"
			   32   undefined4   4   i1   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI_64() {
		return convertCommentsToSpeculative(getExpectedI_64());
	}

	//==============================================================================================
	/*
	 * struct I1 : G1, H {
	 *	  int i11;
	 *	  void _i1f();
	 *	};
	 */
	static CppCompositeType createI1_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G1_struct, CppCompositeType H_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		return is64Bit ? createI1_struct64(vxtManager, G1_struct, H_struct, C_struct, E_struct)
				: createI1_struct32(vxtManager, G1_struct, H_struct, C_struct, E_struct);
	}

	static CppCompositeType createI1_struct32(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType H_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType I1_struct = createStruct32("I1", 28);
			I1_struct.addDirectBaseClass(G1_struct, 0);
			I1_struct.addDirectBaseClass(H_struct, 8);
			I1_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			I1_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			I1_struct.addMember("i11", u4, false, 16);
			return I1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI1_struct64(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType H_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType I1_struct = createStruct64("I1", 48);
			I1_struct.addDirectBaseClass(G1_struct, 0);
			I1_struct.addDirectBaseClass(H_struct, 16);
			I1_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			I1_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr64, 2);
			I1_struct.addMember("i11", u4, false, 32);
			return I1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct I1 : G1, H {
	  int i11;
	  void _i1f();
	};

	class I1	size(28):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 4	| | g11
		| +---
	 8	| +--- (base class H)
	 8	| | {vbptr}
	12	| | h1
		| +---
	16	| i11
		+---
		+--- (virtual base C)
	20	| c1
		+---
		+--- (virtual base E)
	24	| e1
		+---

	I1::$vbtable@G1@:
	 0	| 0
	 1	| 20 (I1d(G1+0)C)
	 2	| 24 (I1d(G1+0)E)

	I1::$vbtable@H@:
	 0	| 0
	 1	| 12 (I1d(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      20       0       4 0
	               E      24       0       8 0
	 */
	//@formatter:on
	private String getExpectedI1_32() {
		String expected =
		//@formatter:off
			"""
			/I1
			pack()
			Structure I1 {
			   0   I1   20      "Self Base"
			   20   C   4      "Virtual Base"
			   24   E   4      "Virtual Base"
			}
			Length: 28 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h1   ""
			}
			Length: 8 Alignment: 4
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   8      "Base"
			   8   H   8      "Base"
			   16   undefined4   4   i11   ""
			}
			Length: 20 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI1_32() {
		return convertCommentsToSpeculative(getExpectedI1_32());
	}

	//@formatter:off
	/*
	struct I1 : G1, H {
	  int i11;
	  void _i1f();
	};

	class I1	size(48):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 8	| | g11
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class H)
	16	| | {vbptr}
	24	| | h1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	32	| i11
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	40	| c1
		+---
		+--- (virtual base E)
	44	| e1
		+---

	I1::$vbtable@G1@:
	 0	| 0
	 1	| 40 (I1d(G1+0)C)
	 2	| 44 (I1d(G1+0)E)

	I1::$vbtable@H@:
	 0	| 0
	 1	| 24 (I1d(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      40       0       4 0
	               E      44       0       8 0
	 */
	//@formatter:on
	private String getExpectedI1_64() {
		String expected =
		//@formatter:off
			"""
			/I1
			pack()
			Structure I1 {
			   0   I1   40      "Self Base"
			   40   C   4      "Virtual Base"
			   44   E   4      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h1   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   undefined4   4   i11   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI1_64() {
		return convertCommentsToSpeculative(getExpectedI1_64());
	}

	//==============================================================================================
	/*
	 * struct I2 : G, H1 {
	 *	  int i21;
	 *	  void _i2f();
	 *	};
	 */
	static CppCompositeType createI2_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G_struct, CppCompositeType H1_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		return is64Bit ? createI2_struct64(vxtManager, G_struct, H1_struct, C_struct, E_struct)
				: createI2_struct32(vxtManager, G_struct, H1_struct, C_struct, E_struct);
	}

	static CppCompositeType createI2_struct32(VxtManager vxtManager, CppCompositeType G_struct,
			CppCompositeType H1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType I2_struct = createStruct32("I2", 28);
			I2_struct.addDirectBaseClass(G_struct, 0);
			I2_struct.addDirectBaseClass(H1_struct, 8);
			I2_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			I2_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			I2_struct.addMember("i21", u4, false, 16);
			return I2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI2_struct64(VxtManager vxtManager, CppCompositeType G_struct,
			CppCompositeType H1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType I2_struct = createStruct64("I2", 48);
			I2_struct.addDirectBaseClass(G_struct, 0);
			I2_struct.addDirectBaseClass(H1_struct, 16);
			I2_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			I2_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr64, 2);
			I2_struct.addMember("i21", u4, false, 32);
			return I2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct I2 : G, H1 {
	  int i21;
	  void _i2f();
	};

	class I2	size(28):
		+---
	 0	| +--- (base class G)
	 0	| | {vbptr}
	 4	| | g1
		| +---
	 8	| +--- (base class H1)
	 8	| | {vbptr}
	12	| | h11
		| +---
	16	| i21
		+---
		+--- (virtual base C)
	20	| c1
		+---
		+--- (virtual base E)
	24	| e1
		+---

	I2::$vbtable@G@:
	 0	| 0
	 1	| 20 (I2d(G+0)C)
	 2	| 24 (I2d(I2+0)E)

	I2::$vbtable@H1@:
	 0	| 0
	 1	| 16 (I2d(H1+0)E)
	 2	| 12 (I2d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      20       0       4 0
	               E      24       0       8 0
	 */
	//@formatter:on
	private String getExpectedI2_32() {
		String expected =
		//@formatter:off
			"""
			/I2
			pack()
			Structure I2 {
			   0   I2   20      "Self Base"
			   20   C   4      "Virtual Base"
			   24   E   4      "Virtual Base"
			}
			Length: 28 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g1   ""
			}
			Length: 8 Alignment: 4
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h11   ""
			}
			Length: 8 Alignment: 4
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   8      "Base"
			   8   H1   8      "Base"
			   16   undefined4   4   i21   ""
			}
			Length: 20 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI2_32() {
		return convertCommentsToSpeculative(getExpectedI2_32());
	}

	//@formatter:off
	/*
	struct I2 : G, H1 {
	  int i21;
	  void _i2f();
	};

	class I2	size(48):
		+---
	 0	| +--- (base class G)
	 0	| | {vbptr}
	 8	| | g1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class H1)
	16	| | {vbptr}
	24	| | h11
	  	| | <alignment member> (size=4)
		| +---
	32	| i21
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	40	| c1
		+---
		+--- (virtual base E)
	44	| e1
		+---

	I2::$vbtable@G@:
	 0	| 0
	 1	| 40 (I2d(G+0)C)
	 2	| 44 (I2d(I2+0)E)

	I2::$vbtable@H1@:
	 0	| 0
	 1	| 28 (I2d(H1+0)E)
	 2	| 24 (I2d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      40       0       4 0
	               E      44       0       8 0
	 */
	//@formatter:on
	private String getExpectedI2_64() {
		String expected =
		//@formatter:off
			"""
			/I2
			pack()
			Structure I2 {
			   0   I2   40      "Self Base"
			   40   C   4      "Virtual Base"
			   44   E   4      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   undefined4   4   i21   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI2_64() {
		return convertCommentsToSpeculative(getExpectedI2_64());
	}

	//==============================================================================================
	/*
	 * struct I3 : G1, H1 {
	 *	  int i31;
	 *	  void _i3f();
	 *	};
	 */
	static CppCompositeType createI3_syntactic_struct32(VxtManager vxtManager) {
		return createI3_syntactic_struct32(vxtManager, null, null, null, null);
	}

	static CppCompositeType createI3_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType G1_struct, CppCompositeType H1_struct, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		CppCompositeType I3_struct = createStruct32("I3", 8);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vxtManager);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct32(vxtManager, C_struct, E_struct);
			}
			if (H1_struct == null) {
				H1_struct = createH1_struct32(vxtManager, E_struct, C_struct);
			}
			I3_struct.addDirectSyntacticBaseClass(G1_struct);
			I3_struct.addDirectSyntacticBaseClass(H1_struct);
			I3_struct.addMember("i31", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I3_struct;
	}

	static CppCompositeType createI3_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G1_struct, CppCompositeType H1_struct, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		return is64Bit ? createI3_struct64(vxtManager, G1_struct, H1_struct, E_struct, C_struct)
				: createI3_struct32(vxtManager, G1_struct, H1_struct, E_struct, C_struct);
	}

	static CppCompositeType createI3_struct32(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType H1_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I3_struct = createStruct32("I3", 28);
			I3_struct.addDirectBaseClass(G1_struct, 0);
			I3_struct.addDirectBaseClass(H1_struct, 8);
			I3_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			I3_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			I3_struct.addMember("i31", u4, false, 16);
			return I3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI3_struct64(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType H1_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I3_struct = createStruct64("I3", 48);
			I3_struct.addDirectBaseClass(G1_struct, 0);
			I3_struct.addDirectBaseClass(H1_struct, 16);
			I3_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			I3_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr64, 2);
			I3_struct.addMember("i31", u4, false, 32);
			return I3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct I3 : G1, H1 {
	  int i31;
	  void _i3f();
	};

	class I3	size(28):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 4	| | g11
		| +---
	 8	| +--- (base class H1)
	 8	| | {vbptr}
	12	| | h11
		| +---
	16	| i31
		+---
		+--- (virtual base C)
	20	| c1
		+---
		+--- (virtual base E)
	24	| e1
		+---

	I3::$vbtable@G1@:
	 0	| 0
	 1	| 20 (I3d(G1+0)C)
	 2	| 24 (I3d(G1+0)E)

	I3::$vbtable@H1@:
	 0	| 0
	 1	| 16 (I3d(H1+0)E)
	 2	| 12 (I3d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      20       0       4 0
	               E      24       0       8 0
	 */
	//@formatter:on
	private String getExpectedI3_32() {
		String expected =
		//@formatter:off
			"""
			/I3
			pack()
			Structure I3 {
			   0   I3   20      "Self Base"
			   20   C   4      "Virtual Base"
			   24   E   4      "Virtual Base"
			}
			Length: 28 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h11   ""
			}
			Length: 8 Alignment: 4
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   8      "Base"
			   8   H1   8      "Base"
			   16   undefined4   4   i31   ""
			}
			Length: 20 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI3_32() {
		return convertCommentsToSpeculative(getExpectedI3_32());
	}

	//@formatter:off
	/*
	struct I3 : G1, H1 {
	  int i31;
	  void _i3f();
	};

	class I3	size(48):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 8	| | g11
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class H1)
	16	| | {vbptr}
	24	| | h11
	  	| | <alignment member> (size=4)
		| +---
	32	| i31
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	40	| c1
		+---
		+--- (virtual base E)
	44	| e1
		+---

	I3::$vbtable@G1@:
	 0	| 0
	 1	| 40 (I3d(G1+0)C)
	 2	| 44 (I3d(G1+0)E)

	I3::$vbtable@H1@:
	 0	| 0
	 1	| 28 (I3d(H1+0)E)
	 2	| 24 (I3d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      40       0       4 0
	               E      44       0       8 0
	 */
	//@formatter:on
	private String getExpectedI3_64() {
		String expected =
		//@formatter:off
			"""
			/I3
			pack()
			Structure I3 {
			   0   I3   40      "Self Base"
			   40   C   4      "Virtual Base"
			   44   E   4      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   16      "Base"
			   16   H1   16      "Base"
			   32   undefined4   4   i31   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI3_64() {
		return convertCommentsToSpeculative(getExpectedI3_64());
	}

	//==============================================================================================
	/*
	 * struct I4 : G1, virtual E, virtual C {
	 *	  int i41;
	 *	  void _i4f();
	 *	};
	 */
	static CppCompositeType createI4_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G1_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		return is64Bit ? createI4_struct64(vxtManager, G1_struct, E_struct, C_struct)
				: createI4_struct32(vxtManager, G1_struct, E_struct, C_struct);
	}

	static CppCompositeType createI4_struct32(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I4_struct = createStruct32("I4", 20);
			I4_struct.addDirectBaseClass(G1_struct, 0);
			I4_struct.addDirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			I4_struct.addDirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			I4_struct.addMember("i41", u4, false, 8);
			return I4_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI4_struct64(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType I4_struct = createStruct64("I4", 32);
		try {
			I4_struct.addDirectBaseClass(G1_struct, 0);
			I4_struct.addDirectVirtualBaseClass(E_struct, 0, vbtptr64, 2);
			I4_struct.addDirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			I4_struct.addMember("i41", u4, false, 16);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I4_struct;
	}

	//@formatter:off
	/*
	struct I4 : G1, virtual E, virtual C {
	  int i41;
	  void _i4f();
	};

	class I4	size(20):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 4	| | g11
		| +---
	 8	| i41
		+---
		+--- (virtual base C)
	12	| c1
		+---
		+--- (virtual base E)
	16	| e1
		+---

	I4::$vbtable@:
	 0	| 0
	 1	| 12 (I4d(G1+0)C)
	 2	| 16 (I4d(G1+0)E)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      12       0       4 0
	               E      16       0       8 0
	 */
	//@formatter:on
	private String getExpectedI4_32() {
		String expected =
		//@formatter:off
			"""
			/I4
			pack()
			Structure I4 {
			   0   I4   12      "Self Base"
			   12   C   4      "Virtual Base"
			   16   E   4      "Virtual Base"
			}
			Length: 20 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4
			/I4/!internal/I4
			pack()
			Structure I4 {
			   0   G1   8      "Base"
			   8   undefined4   4   i41   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI4_32() {
		return convertCommentsToSpeculative(getExpectedI4_32());
	}

	//@formatter:off
	/*
	struct I4 : G1, virtual E, virtual C {
	  int i41;
	  void _i4f();
	};

	class I4	size(32):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 8	| | g11
	  	| | <alignment member> (size=4)
		| +---
	16	| i41
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	24	| c1
		+---
		+--- (virtual base E)
	28	| e1
		+---

	I4::$vbtable@:
	 0	| 0
	 1	| 24 (I4d(G1+0)C)
	 2	| 28 (I4d(G1+0)E)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      24       0       4 0
	               E      28       0       8 0	 */
	//@formatter:on
	private String getExpectedI4_64() {
		String expected =
		//@formatter:off
			"""
			/I4
			pack()
			Structure I4 {
			   0   I4   24      "Self Base"
			   24   C   4      "Virtual Base"
			   28   E   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8
			/I4/!internal/I4
			pack()
			Structure I4 {
			   0   G1   16      "Base"
			   16   undefined4   4   i41   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI4_64() {
		return convertCommentsToSpeculative(getExpectedI4_64());
	}

	//==============================================================================================
	/*
	 * struct I5 : virtual E, virtual C, G1 {
	 *	  int i51;
	 *	  void _i5f();
	 *	};
	 */
	static CppCompositeType createI5_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G1_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		return is64Bit ? createI5_struct64(vxtManager, G1_struct, E_struct, C_struct)
				: createI5_struct32(vxtManager, G1_struct, E_struct, C_struct);
	}

	static CppCompositeType createI5_struct32(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I5_struct = createStruct32("I5", 20);
			I5_struct.addDirectBaseClass(G1_struct, 0);
			I5_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr32, 2); // check this and I4...TODO
			I5_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			I5_struct.addMember("i51", u4, false, 8);
			return I5_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI5_struct64(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I5_struct = createStruct64("I5", 32);
			I5_struct.addDirectBaseClass(G1_struct, 0);
			I5_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr64, 2); // check this and I4...TODO
			I5_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			I5_struct.addMember("i51", u4, false, 16);
			return I5_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct I5 : virtual E, virtual C, G1 {
	  int i51;
	  void _i5f();
	};

	class I5	size(20):
		+---
 	0	| +--- (base class G1)
 	0	| | {vbptr}
 	4	| | g11
		| +---
 	8	| i51
		+---
		+--- (virtual base E)
	12	| e1
		+---
		+--- (virtual base C)
	16	| c1
		+---

	I5::$vbtable@:
 	0	| 0
 	1	| 16 (I5d(G1+0)C)
 	2	| 12 (I5d(G1+0)E)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               E      12       0       8 0
	               C      16       0       4 0
	 */
	//@formatter:on
	private String getExpectedI5_32() {
		String expected =
		//@formatter:off
			"""
			/I5
			pack()
			Structure I5 {
			   0   I5   12      "Self Base"
			   12   E   4      "Virtual Base"
			   16   C   4      "Virtual Base"
			}
			Length: 20 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4
			/I5/!internal/I5
			pack()
			Structure I5 {
			   0   G1   8      "Base"
			   8   undefined4   4   i51   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	/**
	 * Test struct I5 - 32 - speculative placement
	 * <p> THIS TEST STILL HAS PROBLEMS...
	 * <p> The expected output does not match what is the correct layout, but we do not have enough
	 * information (without using vbtable) to create the correct output.  So we are testing our
	 * incorrect result against the known incorrect expected result to cause the test to pass
	 */
	// NOTE: We know that this is an incorrect layout (it matches that of I4), but we are
	//  measuring our result against the best we can determine (C and E virtual bases are
	//  switched from the actual as the Base Class records in the PDB are given in the exact
	//  same order as for I4.  Using the VBT-based algorithm can produce the correct layout, but
	//  the speculative algorithm works without it.
	private String getSpeculatedI5_32() {
		String expected =
		//@formatter:off
			"""
			/I5
			pack()
			Structure I5 {
			   0   I5   12      "Self Base"
			   12   C   4      \"Virtual Base - Speculative Placement\"
			   16   E   4      \"Virtual Base - Speculative Placement\"
			}
			Length: 20 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4
			/I5/!internal/I5
			pack()
			Structure I5 {
			   0   G1   8      "Base"
			   8   undefined4   4   i51   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//@formatter:off
	/*
	struct I5 : virtual E, virtual C, G1 {
	  int i51;
	  void _i5f();
	};

	class I5	size(32):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 8	| | g11
	  	| | <alignment member> (size=4)
		| +---
	16	| i51
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base E)
	24	| e1
		+---
		+--- (virtual base C)
	28	| c1
		+---

	I5::$vbtable@:
	 0	| 0
	 1	| 28 (I5d(G1+0)C)
	 2	| 24 (I5d(G1+0)E)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               E      24       0       8 0
	               C      28       0       4 0
	 */
	//@formatter:on
	private String getExpectedI5_64() {
		String expected =
		//@formatter:off
			"""
			/I5
			pack()
			Structure I5 {
			   0   I5   24      "Self Base"
			   24   E   4      "Virtual Base"
			   28   C   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8
			/I5/!internal/I5
			pack()
			Structure I5 {
			   0   G1   16      "Base"
			   16   undefined4   4   i51   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	/**
	 * Test struct I5 - 64 - speculative placement.
	 * <p> THIS TEST STILL HAS PROBLEMS...
	 * <p> The expected output does not match what is the correct layout, but we do not have enough
	 * information (without using vbtable) to create the correct output.  So we are testing our
	 * incorrect result against the known incorrect expected result to cause the test to pass
	 */
	// NOTE: We know that this is an incorrect layout (it matches that of I4), but we are
	//  measuring our result against the best we can determine (C and E virtual bases are
	//  switched from the actual as the Base Class records in the PDB are given in the exact
	//  same order as for I4.  Using the VBT-based algorithm can produce the correct layout, but
	//  the speculative algorithm works without it.
	private String getSpeculatedI5_64() {
		String expected =
		//@formatter:off
			"""
			/I5
			pack()
			Structure I5 {
			   0   I5   24      "Self Base"
			   24   C   4      \"Virtual Base - Speculative Placement\"
			   28   E   4      \"Virtual Base - Speculative Placement\"
			}
			Length: 32 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8
			/I5/!internal/I5
			pack()
			Structure I5 {
			   0   G1   16      "Base"
			   16   undefined4   4   i51   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================
	/*
	 * struct J1 : I1, I2 {
	 *	  int j11;
	 *	  void j1f();
	 *	};
	 */
	static CppCompositeType createJ1_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType I1_struct, CppCompositeType I2_struct, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		return is64Bit ? createJ1_struct64(vxtManager, I1_struct, I2_struct, E_struct, C_struct)
				: createJ1_struct32(vxtManager, I1_struct, I2_struct, E_struct, C_struct);
	}

	static CppCompositeType createJ1_struct32(VxtManager vxtManager, CppCompositeType I1_struct,
			CppCompositeType I2_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType J1_struct = createStruct32("J1", 52);
			J1_struct.addDirectBaseClass(I1_struct, 0);
			J1_struct.addDirectBaseClass(I2_struct, 20);
			J1_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			J1_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			J1_struct.addMember("j11", u4, false, 40);
			return J1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ1_struct64(VxtManager vxtManager, CppCompositeType I1_struct,
			CppCompositeType I2_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType J1_struct = createStruct64("J1", 96);
			J1_struct.addDirectBaseClass(I1_struct, 0);
			J1_struct.addDirectBaseClass(I2_struct, 40);
			J1_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			J1_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr64, 2);
			J1_struct.addMember("j11", u4, false, 80);
			return J1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct J1 : I1, I2 {
	  int j11;
	  void j1f();
	};

	class J1	size(52):
		+---
 	0	| +--- (base class I1)
 	0	| | +--- (base class G1)
 	0	| | | {vbptr}
 	4	| | | g11
		| | +---
 	8	| | +--- (base class H)
 	8	| | | {vbptr}
	12	| | | h1
		| | +---
	16	| | i11
		| +---
	20	| +--- (base class I2)
	20	| | +--- (base class G)
	20	| | | {vbptr}
	24	| | | g1
		| | +---
	28	| | +--- (base class H1)
	28	| | | {vbptr}
	32	| | | h11
		| | +---
	36	| | i21
		| +---
	40	| j11
		+---
		+--- (virtual base C)
	44	| c1
		+---
		+--- (virtual base E)
	48	| e1
		+---

	J1::$vbtable@G1@:
	 0	| 0
	 1	| 44 (J1d(G1+0)C)
	 2	| 48 (J1d(G1+0)E)

	J1::$vbtable@H@:
	 0	| 0
	 1	| 36 (J1d(H+0)C)

	J1::$vbtable@G@:
	 0	| 0
	 1	| 24 (J1d(G+0)C)
	 2	| 28 (J1d(I2+0)E)

	J1::$vbtable@H1@:
	 0	| 0
	 1	| 20 (J1d(H1+0)E)
	 2	| 16 (J1d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      44       0       4 0
	               E      48       0       8 0
	 */
	//@formatter:on
	private String getExpectedJ1_32() {
		String expected =
		//@formatter:off
			"""
			/J1
			pack()
			Structure J1 {
			   0   J1   44      "Self Base"
			   44   C   4      "Virtual Base"
			   48   E   4      "Virtual Base"
			}
			Length: 52 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g1   ""
			}
			Length: 8 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h1   ""
			}
			Length: 8 Alignment: 4
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h11   ""
			}
			Length: 8 Alignment: 4
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   8      "Base"
			   8   H   8      "Base"
			   16   undefined4   4   i11   ""
			}
			Length: 20 Alignment: 4
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   8      "Base"
			   8   H1   8      "Base"
			   16   undefined4   4   i21   ""
			}
			Length: 20 Alignment: 4
			/J1/!internal/J1
			pack()
			Structure J1 {
			   0   I1   20      "Base"
			   20   I2   20      "Base"
			   40   undefined4   4   j11   ""
			}
			Length: 44 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ1_32() {
		return convertCommentsToSpeculative(getExpectedJ1_32());
	}

	//@formatter:off
	/*
	struct J1 : I1, I2 {
	  int j11;
	  void j1f();
	};

	class J1	size(96):
		+---
	 0	| +--- (base class I1)
	 0	| | +--- (base class G1)
	 0	| | | {vbptr}
	 8	| | | g11
	  	| | | <alignment member> (size=4)
		| | +---
	16	| | +--- (base class H)
	16	| | | {vbptr}
	24	| | | h1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	32	| | i11
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class I2)
	40	| | +--- (base class G)
	40	| | | {vbptr}
	48	| | | g1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	56	| | +--- (base class H1)
	56	| | | {vbptr}
	64	| | | h11
	  	| | | <alignment member> (size=4)
		| | +---
	72	| | i21
	  	| | <alignment member> (size=4)
		| +---
	80	| j11
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	88	| c1
		+---
		+--- (virtual base E)
	92	| e1
		+---

	J1::$vbtable@G1@:
	 0	| 0
	 1	| 88 (J1d(G1+0)C)
	 2	| 92 (J1d(G1+0)E)

	J1::$vbtable@H@:
	 0	| 0
	 1	| 72 (J1d(H+0)C)

	J1::$vbtable@G@:
	 0	| 0
	 1	| 48 (J1d(G+0)C)
	 2	| 52 (J1d(I2+0)E)

	J1::$vbtable@H1@:
	 0	| 0
	 1	| 36 (J1d(H1+0)E)
	 2	| 32 (J1d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      88       0       4 0
	               E      92       0       8 0
	 */
	//@formatter:on
	private String getExpectedJ1_64() {
		String expected =
		//@formatter:off
			"""
			/J1
			pack()
			Structure J1 {
			   0   J1   88      "Self Base"
			   88   C   4      "Virtual Base"
			   92   E   4      "Virtual Base"
			}
			Length: 96 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   undefined4   4   i11   ""
			}
			Length: 40 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   undefined4   4   i21   ""
			}
			Length: 40 Alignment: 8
			/J1/!internal/J1
			pack()
			Structure J1 {
			   0   I1   40      "Base"
			   40   I2   40      "Base"
			   80   undefined4   4   j11   ""
			}
			Length: 88 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ1_64() {
		return convertCommentsToSpeculative(getExpectedJ1_64());
	}

	//==============================================================================================
	/*
	 * struct J2 : I2, I1 {
	 *	  int j21;
	 *	  void j2f();
	 *	};
	 */
	static CppCompositeType createJ2_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType I2_struct, CppCompositeType I1_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		return is64Bit ? createJ2_struct64(vxtManager, I2_struct, I1_struct, C_struct, E_struct)
				: createJ2_struct32(vxtManager, I2_struct, I1_struct, C_struct, E_struct);
	}

	static CppCompositeType createJ2_struct32(VxtManager vxtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType J2_struct = createStruct32("J2", 52);
			J2_struct.addDirectBaseClass(I2_struct, 0);
			J2_struct.addDirectBaseClass(I1_struct, 20);
			J2_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			J2_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			J2_struct.addMember("j21", u4, false, 40);
			return J2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ2_struct64(VxtManager vxtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType J2_struct = createStruct64("J2", 96);
			J2_struct.addDirectBaseClass(I2_struct, 0);
			J2_struct.addDirectBaseClass(I1_struct, 40);
			J2_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			J2_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr64, 2);
			J2_struct.addMember("j21", u4, false, 80);
			return J2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct J2 : I2, I1 {
	  int j21;
	  void j2f();
	};

	class J2	size(52):
		+---
	 0	| +--- (base class I2)
	 0	| | +--- (base class G)
	 0	| | | {vbptr}
	 4	| | | g1
		| | +---
	 8	| | +--- (base class H1)
	 8	| | | {vbptr}
	12	| | | h11
		| | +---
	16	| | i21
		| +---
	20	| +--- (base class I1)
	20	| | +--- (base class G1)
	20	| | | {vbptr}
	24	| | | g11
		| | +---
	28	| | +--- (base class H)
	28	| | | {vbptr}
	32	| | | h1
		| | +---
	36	| | i11
		| +---
	40	| j21
		+---
		+--- (virtual base C)
	44	| c1
		+---
		+--- (virtual base E)
	48	| e1
		+---

	J2::$vbtable@G@:
	 0	| 0
	 1	| 44 (J2d(G+0)C)
	 2	| 48 (J2d(I2+0)E)

	J2::$vbtable@H1@:
	 0	| 0
	 1	| 40 (J2d(H1+0)E)
	 2	| 36 (J2d(H1+0)C)

	J2::$vbtable@G1@:
	 0	| 0
	 1	| 24 (J2d(G1+0)C)
	 2	| 28 (J2d(G1+0)E)

	J2::$vbtable@H@:
	 0	| 0
	 1	| 16 (J2d(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      44       0       4 0
	               E      48       0       8 0
	 */
	//@formatter:on
	private String getExpectedJ2_32() {
		String expected =
		//@formatter:off
			"""
			/J2
			pack()
			Structure J2 {
			   0   J2   44      "Self Base"
			   44   C   4      "Virtual Base"
			   48   E   4      "Virtual Base"
			}
			Length: 52 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g1   ""
			}
			Length: 8 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h1   ""
			}
			Length: 8 Alignment: 4
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h11   ""
			}
			Length: 8 Alignment: 4
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   8      "Base"
			   8   H   8      "Base"
			   16   undefined4   4   i11   ""
			}
			Length: 20 Alignment: 4
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   8      "Base"
			   8   H1   8      "Base"
			   16   undefined4   4   i21   ""
			}
			Length: 20 Alignment: 4
			/J2/!internal/J2
			pack()
			Structure J2 {
			   0   I2   20      "Base"
			   20   I1   20      "Base"
			   40   undefined4   4   j21   ""
			}
			Length: 44 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ2_32() {
		return convertCommentsToSpeculative(getExpectedJ2_32());
	}

	//@formatter:off
	/*
	struct J2 : I2, I1 {
	  int j21;
	  void j2f();
	};

	class J2	size(96):
		+---
	 0	| +--- (base class I2)
	 0	| | +--- (base class G)
	 0	| | | {vbptr}
	 8	| | | g1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	16	| | +--- (base class H1)
	16	| | | {vbptr}
	24	| | | h11
	  	| | | <alignment member> (size=4)
		| | +---
	32	| | i21
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class I1)
	40	| | +--- (base class G1)
	40	| | | {vbptr}
	48	| | | g11
	  	| | | <alignment member> (size=4)
		| | +---
	56	| | +--- (base class H)
	56	| | | {vbptr}
	64	| | | h1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	72	| | i11
	  	| | <alignment member> (size=4)
		| +---
	80	| j21
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	88	| c1
		+---
		+--- (virtual base E)
	92	| e1
		+---

	J2::$vbtable@G@:
	 0	| 0
	 1	| 88 (J2d(G+0)C)
	 2	| 92 (J2d(I2+0)E)

	J2::$vbtable@H1@:
	 0	| 0
	 1	| 76 (J2d(H1+0)E)
	 2	| 72 (J2d(H1+0)C)

	J2::$vbtable@G1@:
	 0	| 0
	 1	| 48 (J2d(G1+0)C)
	 2	| 52 (J2d(G1+0)E)

	J2::$vbtable@H@:
	 0	| 0
 	1	| 32 (J2d(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      88       0       4 0
	               E      92       0       8 0
	 */
	//@formatter:on
	private String getExpectedJ2_64() {
		String expected =
		//@formatter:off
			"""
			/J2
			pack()
			Structure J2 {
			   0   J2   88      "Self Base"
			   88   C   4      "Virtual Base"
			   92   E   4      "Virtual Base"
			}
			Length: 96 Alignment: 8
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   undefined4   4   i11   ""
			}
			Length: 40 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   undefined4   4   i21   ""
			}
			Length: 40 Alignment: 8
			/J2/!internal/J2
			pack()
			Structure J2 {
			   0   I2   40      "Base"
			   40   I1   40      "Base"
			   80   undefined4   4   j21   ""
			}
			Length: 88 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ2_64() {
		return convertCommentsToSpeculative(getExpectedJ2_64());
	}

	//==============================================================================================
	/*
	 * struct J3 : I2, I1, A {
	 *	  int j31;
	 *	  void j3f();
	 *	};
	 */
	static CppCompositeType createJ3_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType I2_struct, CppCompositeType I1_struct, CppCompositeType A_struct,
			CppCompositeType C_struct, CppCompositeType E_struct) {
		return is64Bit
				? createJ3_struct64(vxtManager, I2_struct, I1_struct, A_struct, C_struct, E_struct)
				: createJ3_struct32(vxtManager, I2_struct, I1_struct, A_struct, C_struct, E_struct);
	}

	static CppCompositeType createJ3_struct32(VxtManager vxtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType A_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType J3_struct = createStruct32("J3", 60);
			J3_struct.addDirectBaseClass(I2_struct, 0);
			J3_struct.addDirectBaseClass(I1_struct, 20);
			J3_struct.addDirectBaseClass(A_struct, 40);
			J3_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			J3_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			J3_struct.addMember("j31", u4, false, 48);
			return J3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ3_struct64(VxtManager vxtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType A_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType J3_struct = createStruct64("J3", 104);
			J3_struct.addDirectBaseClass(I2_struct, 0);
			J3_struct.addDirectBaseClass(I1_struct, 40);
			J3_struct.addDirectBaseClass(A_struct, 80);
			J3_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			J3_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr64, 2);
			J3_struct.addMember("j31", u4, false, 88);
			return J3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct J3 : I2, I1, A {
	  int j31;
	  void j3f();
	};

	class J3	size(60):
		+---
	 0	| +--- (base class I2)
	 0	| | +--- (base class G)
	 0	| | | {vbptr}
	 4	| | | g1
		| | +---
	 8	| | +--- (base class H1)
	 8	| | | {vbptr}
	12	| | | h11
		| | +---
	16	| | i21
		| +---
	20	| +--- (base class I1)
	20	| | +--- (base class G1)
	20	| | | {vbptr}
	24	| | | g11
		| | +---
	28	| | +--- (base class H)
	28	| | | {vbptr}
	32	| | | h1
		| | +---
	36	| | i11
		| +---
	40	| +--- (base class A)
	40	| | c
	  	| | <alignment member> (size=3)
	44	| | i
		| +---
	48	| j31
		+---
		+--- (virtual base C)
	52	| c1
		+---
		+--- (virtual base E)
	56	| e1
		+---

	J3::$vbtable@G@:
	 0	| 0
	 1	| 52 (J3d(G+0)C)
	 2	| 56 (J3d(I2+0)E)

	J3::$vbtable@H1@:
	 0	| 0
	 1	| 48 (J3d(H1+0)E)
	 2	| 44 (J3d(H1+0)C)

	J3::$vbtable@G1@:
	 0	| 0
	 1	| 32 (J3d(G1+0)C)
	 2	| 36 (J3d(G1+0)E)

	J3::$vbtable@H@:
	 0	| 0
	 1	| 24 (J3d(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      52       0       4 0
	               E      56       0       8 0
	 */
	//@formatter:on
	private String getExpectedJ3_32() {
		String expected =
		//@formatter:off
			"""
			/J3
			pack()
			Structure J3 {
			   0   J3   52      "Self Base"
			   52   C   4      "Virtual Base"
			   56   E   4      "Virtual Base"
			}
			Length: 60 Alignment: 4
			/A
			pack()
			Structure A {
			   0   undefined1   1   c   ""
			   4   undefined4   4   i   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g1   ""
			}
			Length: 8 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h1   ""
			}
			Length: 8 Alignment: 4
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h11   ""
			}
			Length: 8 Alignment: 4
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   8      "Base"
			   8   H   8      "Base"
			   16   undefined4   4   i11   ""
			}
			Length: 20 Alignment: 4
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   8      "Base"
			   8   H1   8      "Base"
			   16   undefined4   4   i21   ""
			}
			Length: 20 Alignment: 4
			/J3/!internal/J3
			pack()
			Structure J3 {
			   0   I2   20      "Base"
			   20   I1   20      "Base"
			   40   A   8      "Base"
			   48   undefined4   4   j31   ""
			}
			Length: 52 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ3_32() {
		return convertCommentsToSpeculative(getExpectedJ3_32());
	}

	//@formatter:off
	/*
	struct J3 : I2, I1, A {
	  int j31;
	  void j3f();
	};

	class J3	size(104):
		+---
	 0	| +--- (base class I2)
	 0	| | +--- (base class G)
	 0	| | | {vbptr}
	 8	| | | g1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	16	| | +--- (base class H1)
	16	| | | {vbptr}
	24	| | | h11
	  	| | | <alignment member> (size=4)
		| | +---
	32	| | i21
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class I1)
	40	| | +--- (base class G1)
	40	| | | {vbptr}
	48	| | | g11
	  	| | | <alignment member> (size=4)
		| | +---
	56	| | +--- (base class H)
	56	| | | {vbptr}
	64	| | | h1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	72	| | i11
	  	| | <alignment member> (size=4)
		| +---
	80	| +--- (base class A)
	80	| | c
	  	| | <alignment member> (size=3)
	84	| | i
		| +---
	88	| j31
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	96	| c1
		+---
		+--- (virtual base E)
	100	| e1
		+---

	J3::$vbtable@G@:
	 0	| 0
	 1	| 96 (J3d(G+0)C)
	 2	| 100 (J3d(I2+0)E)

	J3::$vbtable@H1@:
	 0	| 0
	 1	| 84 (J3d(H1+0)E)
	 2	| 80 (J3d(H1+0)C)

	J3::$vbtable@G1@:
	 0	| 0
	 1	| 56 (J3d(G1+0)C)
	 2	| 60 (J3d(G1+0)E)

	J3::$vbtable@H@:
	 0	| 0
	 1	| 40 (J3d(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      96       0       4 0
	               E     100       0       8 0
	 */
	//@formatter:on
	private String getExpectedJ3_64() {
		String expected =
		//@formatter:off
			"""
			/J3
			pack()
			Structure J3 {
			   0   J3   96      "Self Base"
			   96   C   4      "Virtual Base"
			   100   E   4      "Virtual Base"
			}
			Length: 104 Alignment: 8
			/A
			pack()
			Structure A {
			   0   undefined1   1   c   ""
			   4   undefined4   4   i   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   undefined4   4   i11   ""
			}
			Length: 40 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   undefined4   4   i21   ""
			}
			Length: 40 Alignment: 8
			/J3/!internal/J3
			pack()
			Structure J3 {
			   0   I2   40      "Base"
			   40   I1   40      "Base"
			   80   A   8      "Base"
			   88   undefined4   4   j31   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ3_64() {
		return convertCommentsToSpeculative(getExpectedJ3_64());
	}

	//==============================================================================================
	/*
	 * struct J4 : I3, GG1, I, A, virtual GG2, virtual GG3 {
	 *	  int j41;
	 *	  void j4f();
	 *	};
	 */
	static CppCompositeType createJ4_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType I3_struct, CppCompositeType GG1_struct, CppCompositeType I_struct,
			CppCompositeType A_struct, CppCompositeType GG2_struct, CppCompositeType GG3_struct,
			CppCompositeType C_struct, CppCompositeType E_struct, CppCompositeType CC1_struct,
			CppCompositeType CC2_struct) {
		return is64Bit
				? createJ4_struct64(vxtManager, I3_struct, GG1_struct, I_struct, A_struct,
					GG2_struct, GG3_struct, C_struct, E_struct, CC1_struct, CC2_struct)
				: createJ4_struct32(vxtManager, I3_struct, GG1_struct, I_struct, A_struct,
					GG2_struct, GG3_struct, C_struct, E_struct, CC1_struct, CC2_struct);
	}

	static CppCompositeType createJ4_struct32(VxtManager vxtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		try {
			CppCompositeType J4_struct = createStruct32("J4", 92);
			J4_struct.addDirectBaseClass(I3_struct, 0);
			J4_struct.addDirectBaseClass(GG1_struct, 20);
			J4_struct.addDirectBaseClass(I_struct, 28);
			J4_struct.addDirectBaseClass(A_struct, 48);
			J4_struct.addDirectVirtualBaseClass(GG2_struct, 0, vbtptr32, 5);
			J4_struct.addDirectVirtualBaseClass(GG3_struct, 0, vbtptr32, 6);
			J4_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			J4_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			J4_struct.addIndirectVirtualBaseClass(CC1_struct, 0, vbtptr32, 3);
			J4_struct.addIndirectVirtualBaseClass(CC2_struct, 0, vbtptr32, 4);
			J4_struct.addMember("j41", u4, false, 56);
			return J4_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ4_struct64(VxtManager vxtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		try {
			CppCompositeType J4_struct = createStruct64("J4", 160);
			J4_struct.addDirectBaseClass(I3_struct, 0);
			J4_struct.addDirectBaseClass(GG1_struct, 40);
			J4_struct.addDirectBaseClass(I_struct, 56);
			J4_struct.addDirectBaseClass(A_struct, 96);
			J4_struct.addDirectVirtualBaseClass(GG2_struct, 0, vbtptr64, 5);
			J4_struct.addDirectVirtualBaseClass(GG3_struct, 0, vbtptr64, 6);
			J4_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr64, 1);
			J4_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr64, 2);
			J4_struct.addIndirectVirtualBaseClass(CC1_struct, 0, vbtptr64, 3);
			J4_struct.addIndirectVirtualBaseClass(CC2_struct, 0, vbtptr64, 4);
			J4_struct.addMember("j41", u4, false, 104);
			return J4_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct J4 : I3, GG1, I, A, virtual GG2, virtual GG3 {
	  int j41;
	  void j4f();
	};

	class J4	size(92):
		+---
	 0	| +--- (base class I3)
	 0	| | +--- (base class G1)
	 0	| | | {vbptr}
	 4	| | | g11
		| | +---
	 8	| | +--- (base class H1)
	 8	| | | {vbptr}
	12	| | | h11
		| | +---
	16	| | i31
		| +---
	20	| +--- (base class GG1)
	20	| | {vbptr}
	24	| | gg11
		| +---
	28	| +--- (base class I)
	28	| | +--- (base class G)
	28	| | | {vbptr}
	32	| | | g1
		| | +---
	36	| | +--- (base class H)
	36	| | | {vbptr}
	40	| | | h1
		| | +---
	44	| | i1
		| +---
	48	| +--- (base class A)
	48	| | c
	  	| | <alignment member> (size=3)
	52	| | i
		| +---
	56	| j41
		+---
		+--- (virtual base C)
	60	| c1
		+---
		+--- (virtual base E)
	64	| e1
		+---
		+--- (virtual base CC1)
	68	| cc11
		+---
		+--- (virtual base CC2)
	72	| cc21
		+---
		+--- (virtual base GG2)
	76	| {vbptr}
	80	| gg21
		+---
		+--- (virtual base GG3)
	84	| {vbptr}
	88	| gg31
		+---

	J4::$vbtable@G1@:
	 0	| 0
	 1	| 60 (J4d(G1+0)C)
	 2	| 64 (J4d(G1+0)E)
	 3	| 68 (J4d(J4+0)CC1)
	 4	| 72 (J4d(J4+0)CC2)
	 5	| 76 (J4d(J4+0)GG2)
	 6	| 84 (J4d(J4+0)GG3)

	J4::$vbtable@H1@:
	 0	| 0
	 1	| 56 (J4d(H1+0)E)
 	2	| 52 (J4d(H1+0)C)

	J4::$vbtable@GG1@:
	 0	| 0
	 1	| 48 (J4d(GG1+0)CC1)

	J4::$vbtable@G@:
	 0	| 0
	 1	| 32 (J4d(G+0)C)

	J4::$vbtable@H@:
	 0	| 0
	 1	| 24 (J4d(H+0)C)

	J4::$vbtable@GG2@:
	 0	| 0
	 1	| -4 (J4d(GG2+0)CC2)

	J4::$vbtable@GG3@:
	 0	| 0
	 1	| -12 (J4d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      60       0       4 0
	               E      64       0       8 0
	             CC1      68       0      12 0
	             CC2      72       0      16 0
	             GG2      76       0      20 0
	             GG3      84       0      24 0
	 */
	//@formatter:on
	private String getExpectedJ4_32() {
		String expected =
		//@formatter:off
			"""
			/J4
			pack()
			Structure J4 {
			   0   J4   60      "Self Base"
			   60   C   4      "Virtual Base"
			   64   E   4      "Virtual Base"
			   68   CC1   4      "Virtual Base"
			   72   CC2   4      "Virtual Base"
			   76   GG2   8      "Virtual Base"
			   84   GG3   8      "Virtual Base"
			}
			Length: 92 Alignment: 4
			/A
			pack()
			Structure A {
			   0   undefined1   1   c   ""
			   4   undefined4   4   i   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/CC1
			pack()
			Structure CC1 {
			   0   undefined4   4   cc11   ""
			}
			Length: 4 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g1   ""
			}
			Length: 8 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg11   ""
			}
			Length: 8 Alignment: 4
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg21   ""
			}
			Length: 8 Alignment: 4
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg31   ""
			}
			Length: 8 Alignment: 4
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h1   ""
			}
			Length: 8 Alignment: 4
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h11   ""
			}
			Length: 8 Alignment: 4
			/I/!internal/I
			pack()
			Structure I {
			   0   G   8      "Base"
			   8   H   8      "Base"
			   16   undefined4   4   i1   ""
			}
			Length: 20 Alignment: 4
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   8      "Base"
			   8   H1   8      "Base"
			   16   undefined4   4   i31   ""
			}
			Length: 20 Alignment: 4
			/J4/!internal/J4
			pack()
			Structure J4 {
			   0   I3   20      "Base"
			   20   GG1   8      "Base"
			   28   I   20      "Base"
			   48   A   8      "Base"
			   56   undefined4   4   j41   ""
			}
			Length: 60 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ4_32() {
		return convertCommentsToSpeculative(getExpectedJ4_32());
	}

	//@formatter:off
	/*
	struct J4 : I3, GG1, I, A, virtual GG2, virtual GG3 {
	  int j41;
	  void j4f();
	};

	class J4	size(160):
		+---
	 0	| +--- (base class I3)
	 0	| | +--- (base class G1)
	 0	| | | {vbptr}
	 8	| | | g11
	  	| | | <alignment member> (size=4)
		| | +---
	16	| | +--- (base class H1)
	16	| | | {vbptr}
	24	| | | h11
	  	| | | <alignment member> (size=4)
		| | +---
	32	| | i31
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class GG1)
	40	| | {vbptr}
	48	| | gg11
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	56	| +--- (base class I)
	56	| | +--- (base class G)
	56	| | | {vbptr}
	64	| | | g1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	72	| | +--- (base class H)
	72	| | | {vbptr}
	80	| | | h1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	88	| | i1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	96	| +--- (base class A)
	96	| | c
	  	| | <alignment member> (size=3)
	100	| | i
		| +---
	104	| j41
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	112	| c1
		+---
		+--- (virtual base E)
	116	| e1
		+---
		+--- (virtual base CC1)
	120	| cc11
		+---
		+--- (virtual base CC2)
	124	| cc21
		+---
		+--- (virtual base GG2)
	128	| {vbptr}
	136	| gg21
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base GG3)
	144	| {vbptr}
	152	| gg31
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---

	J4::$vbtable@G1@:
	 0	| 0
	 1	| 112 (J4d(G1+0)C)
	 2	| 116 (J4d(G1+0)E)
	 3	| 120 (J4d(J4+0)CC1)
	 4	| 124 (J4d(J4+0)CC2)
	 5	| 128 (J4d(J4+0)GG2)
	 6	| 144 (J4d(J4+0)GG3)

	J4::$vbtable@H1@:
	 0	| 0
	 1	| 100 (J4d(H1+0)E)
	 2	| 96 (J4d(H1+0)C)

	J4::$vbtable@GG1@:
	 0	| 0
	 1	| 80 (J4d(GG1+0)CC1)

	J4::$vbtable@G@:
	 0	| 0
	 1	| 56 (J4d(G+0)C)

	J4::$vbtable@H@:
	 0	| 0
	 1	| 40 (J4d(H+0)C)

	J4::$vbtable@GG2@:
	 0	| 0
	 1	| -4 (J4d(GG2+0)CC2)

	J4::$vbtable@GG3@:
	 0	| 0
	 1	| -20 (J4d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C     112       0       4 0
	               E     116       0       8 0
	             CC1     120       0      12 0
	             CC2     124       0      16 0
	             GG2     128       0      20 0
	             GG3     144       0      24 0
	 */
	//@formatter:on
	private String getExpectedJ4_64() {
		String expected =
		//@formatter:off
			"""
			/J4
			pack()
			Structure J4 {
			   0   J4   112      "Self Base"
			   112   C   4      "Virtual Base"
			   116   E   4      "Virtual Base"
			   120   CC1   4      "Virtual Base"
			   124   CC2   4      "Virtual Base"
			   128   GG2   16      "Virtual Base"
			   144   GG3   16      "Virtual Base"
			}
			Length: 160 Alignment: 8
			/A
			pack()
			Structure A {
			   0   undefined1   1   c   ""
			   4   undefined4   4   i   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/CC1
			pack()
			Structure CC1 {
			   0   undefined4   4   cc11   ""
			}
			Length: 4 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg11   ""
			}
			Length: 16 Alignment: 8
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg21   ""
			}
			Length: 16 Alignment: 8
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg31   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I/!internal/I
			pack()
			Structure I {
			   0   G   16      "Base"
			   16   H   16      "Base"
			   32   undefined4   4   i1   ""
			}
			Length: 40 Alignment: 8
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   16      "Base"
			   16   H1   16      "Base"
			   32   undefined4   4   i31   ""
			}
			Length: 40 Alignment: 8
			/J4/!internal/J4
			pack()
			Structure J4 {
			   0   I3   40      "Base"
			   40   GG1   16      "Base"
			   56   I   40      "Base"
			   96   A   8      "Base"
			   104   undefined4   4   j41   ""
			}
			Length: 112 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ4_64() {
		return convertCommentsToSpeculative(getExpectedJ4_64());
	}

	//==============================================================================================
	/*
	 * struct J5 : virtual GG2, virtual GG3, I3, GG1, I, A {
	 *	  int j51;
	 *	  void j5f();
	 *	};
	 */
	static CppCompositeType createJ5_syntactic_struct32(VxtManager vxtManager) {
		return createJ5_syntactic_struct32(vxtManager, null, null, null, null, null, null, null,
			null, null, null);
	}

	static CppCompositeType createJ5_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType I3_struct, CppCompositeType GG1_struct, CppCompositeType I_struct,
			CppCompositeType A_struct, CppCompositeType GG2_struct, CppCompositeType GG3_struct,
			CppCompositeType C_struct, CppCompositeType E_struct, CppCompositeType CC1_struct,
			CppCompositeType CC2_struct) {
		CppCompositeType J5_struct = createStruct32("J5", 0); // TODO need without size
		try {
			if (A_struct == null) {
				A_struct = createA_syntactic_struct32(vxtManager);
			}
			if (C_struct == null) {
				C_struct = createC_syntactic_struct32(vxtManager);
			}
			if (E_struct == null) {
				E_struct = createE_syntactic_struct32(vxtManager);
			}
			if (CC1_struct == null) {
				CC1_struct = createCC1_syntactic_struct32(vxtManager);
			}
			if (CC2_struct == null) {
				CC2_struct = createCC2_syntactic_struct32(vxtManager);
			}
			if (I3_struct == null) {
				CppCompositeType G1_struct =
					createG1_syntactic_struct32(vxtManager, C_struct, E_struct);
				CppCompositeType H1_struct =
					createH1_syntactic_struct32(vxtManager, E_struct, C_struct);
				I3_struct = createI3_syntactic_struct32(vxtManager, G1_struct, H1_struct, E_struct,
					C_struct);
			}
			if (GG1_struct == null) {
				GG1_struct = createGG1_syntactic_struct32(vxtManager, CC1_struct);
			}
			if (I_struct == null) {
				CppCompositeType G_struct = createG_syntactic_struct32(vxtManager, C_struct);
				CppCompositeType H_struct = createH_syntactic_struct32(vxtManager, C_struct);
				I_struct = createI_syntactic_struct32(vxtManager, G_struct, H_struct, C_struct);
			}
			if (GG2_struct == null) {
				GG2_struct = createGG2_syntactic_struct32(vxtManager, CC2_struct);
			}
			if (GG3_struct == null) {
				GG3_struct = createGG3_syntactic_struct32(vxtManager, CC2_struct);
			}
			J5_struct.addVirtualSyntacticBaseClass(GG2_struct);
			J5_struct.addVirtualSyntacticBaseClass(GG3_struct);
			J5_struct.addDirectSyntacticBaseClass(I3_struct);
			J5_struct.addDirectSyntacticBaseClass(GG1_struct);
			J5_struct.addDirectSyntacticBaseClass(I_struct);
			J5_struct.addDirectSyntacticBaseClass(A_struct);
			J5_struct.addMember("j51", u4, false, 0); // TODO nned syntactic without index
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J5_struct;
	}

	static CppCompositeType createJ5_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType I3_struct, CppCompositeType GG1_struct, CppCompositeType I_struct,
			CppCompositeType A_struct, CppCompositeType GG2_struct, CppCompositeType GG3_struct,
			CppCompositeType C_struct, CppCompositeType E_struct, CppCompositeType CC1_struct,
			CppCompositeType CC2_struct) {
		return is64Bit
				? createJ5_struct64(vxtManager, I3_struct, GG1_struct, I_struct, A_struct,
					GG2_struct, GG3_struct, C_struct, E_struct, CC1_struct, CC2_struct)
				: createJ5_struct32(vxtManager, I3_struct, GG1_struct, I_struct, A_struct,
					GG2_struct, GG3_struct, C_struct, E_struct, CC1_struct, CC2_struct);
	}

	static CppCompositeType createJ5_struct32(VxtManager vxtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		try {
			CppCompositeType J5_struct = createStruct32("J5", 92);
			J5_struct.addDirectBaseClass(I3_struct, 0);
			J5_struct.addDirectBaseClass(GG1_struct, 20);
			J5_struct.addDirectBaseClass(I_struct, 28);
			J5_struct.addDirectBaseClass(A_struct, 48);
			J5_struct.addDirectVirtualBaseClass(GG2_struct, 0, vbtptr32, 4);
			J5_struct.addDirectVirtualBaseClass(GG3_struct, 0, vbtptr32, 5);
			J5_struct.addIndirectVirtualBaseClass(CC2_struct, 0, vbtptr32, 3);
			J5_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			J5_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			J5_struct.addIndirectVirtualBaseClass(CC1_struct, 0, vbtptr32, 6);
			J5_struct.addMember("j51", u4, false, 56);
			return J5_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ5_struct64(VxtManager vxtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		try {
			CppCompositeType J5_struct = createStruct64("J5", 164);
			J5_struct.addDirectBaseClass(I3_struct, 0);
			J5_struct.addDirectBaseClass(GG1_struct, 40);
			J5_struct.addDirectBaseClass(I_struct, 56);
			J5_struct.addDirectBaseClass(A_struct, 96);
			J5_struct.addDirectVirtualBaseClass(GG2_struct, 0, vbtptr32, 4);
			J5_struct.addDirectVirtualBaseClass(GG3_struct, 0, vbtptr32, 5);
			J5_struct.addIndirectVirtualBaseClass(CC2_struct, 0, vbtptr32, 3);
			J5_struct.addIndirectVirtualBaseClass(C_struct, 0, vbtptr32, 1);
			J5_struct.addIndirectVirtualBaseClass(E_struct, 0, vbtptr32, 2);
			J5_struct.addIndirectVirtualBaseClass(CC1_struct, 0, vbtptr32, 6);
			J5_struct.addMember("j51", u4, false, 104);
			return J5_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct J5 : virtual GG2, virtual GG3, I3, GG1, I, A {
	  int j51;
	  void j5f();
	};

	class J5	size(92):
		+---
	 0	| +--- (base class I3)
	 0	| | +--- (base class G1)
	 0	| | | {vbptr}
	 4	| | | g11
		| | +---
	 8	| | +--- (base class H1)
	 8	| | | {vbptr}
	12	| | | h11
		| | +---
	16	| | i31
		| +---
	20	| +--- (base class GG1)
	20	| | {vbptr}
	24	| | gg11
		| +---
	28	| +--- (base class I)
	28	| | +--- (base class G)
	28	| | | {vbptr}
	32	| | | g1
		| | +---
	36	| | +--- (base class H)
	36	| | | {vbptr}
	40	| | | h1
		| | +---
	44	| | i1
		| +---
	48	| +--- (base class A)
	48	| | c
	  	| | <alignment member> (size=3)
	52	| | i
		| +---
	56	| j51
		+---
		+--- (virtual base CC2)
	60	| cc21
		+---
		+--- (virtual base GG2)
	64	| {vbptr}
	68	| gg21
		+---
		+--- (virtual base GG3)
	72	| {vbptr}
	76	| gg31
		+---
		+--- (virtual base C)
	80	| c1
		+---
		+--- (virtual base E)
	84	| e1
		+---
		+--- (virtual base CC1)
	88	| cc11
		+---

	J5::$vbtable@G1@:
	 0	| 0
	 1	| 80 (J5d(G1+0)C)
	 2	| 84 (J5d(G1+0)E)
	 3	| 60 (J5d(J5+0)CC2)
	 4	| 64 (J5d(J5+0)GG2)
	 5	| 72 (J5d(J5+0)GG3)
	 6	| 88 (J5d(J5+0)CC1)

	J5::$vbtable@H1@:
	 0	| 0
	 1	| 76 (J5d(H1+0)E)
	 2	| 72 (J5d(H1+0)C)

	J5::$vbtable@GG1@:
	 0	| 0
	 1	| 68 (J5d(GG1+0)CC1)

	J5::$vbtable@G@:
	 0	| 0
	 1	| 52 (J5d(G+0)C)

	J5::$vbtable@H@:
	 0	| 0
	 1	| 44 (J5d(H+0)C)

	J5::$vbtable@GG2@:
	 0	| 0
	 1	| -4 (J5d(GG2+0)CC2)

	J5::$vbtable@GG3@:
	 0	| 0
	 1	| -12 (J5d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC2      60       0      12 0
	             GG2      64       0      16 0
	             GG3      72       0      20 0
	               C      80       0       4 0
	               E      84       0       8 0
	             CC1      88       0      24 0
	 */
	//@formatter:on
	private String getExpectedJ5_32() {
		String expected =
		//@formatter:off
			"""
			/J5
			pack()
			Structure J5 {
			   0   J5   60      "Self Base"
			   60   CC2   4      "Virtual Base"
			   64   GG2   8      "Virtual Base"
			   72   GG3   8      "Virtual Base"
			   80   C   4      "Virtual Base"
			   84   E   4      "Virtual Base"
			   88   CC1   4      "Virtual Base"
			}
			Length: 92 Alignment: 4
			/A
			pack()
			Structure A {
			   0   undefined1   1   c   ""
			   4   undefined4   4   i   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/CC1
			pack()
			Structure CC1 {
			   0   undefined4   4   cc11   ""
			}
			Length: 4 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g1   ""
			}
			Length: 8 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   g11   ""
			}
			Length: 8 Alignment: 4
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg11   ""
			}
			Length: 8 Alignment: 4
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg21   ""
			}
			Length: 8 Alignment: 4
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg31   ""
			}
			Length: 8 Alignment: 4
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h1   ""
			}
			Length: 8 Alignment: 4
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   h11   ""
			}
			Length: 8 Alignment: 4
			/I/!internal/I
			pack()
			Structure I {
			   0   G   8      "Base"
			   8   H   8      "Base"
			   16   undefined4   4   i1   ""
			}
			Length: 20 Alignment: 4
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   8      "Base"
			   8   H1   8      "Base"
			   16   undefined4   4   i31   ""
			}
			Length: 20 Alignment: 4
			/J5/!internal/J5
			pack()
			Structure J5 {
			   0   I3   20      "Base"
			   20   GG1   8      "Base"
			   28   I   20      "Base"
			   48   A   8      "Base"
			   56   undefined4   4   j51   ""
			}
			Length: 60 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	// TODO: Need to work on layout algorithm... believe we can do better, but don't have
	//  a decision on the best speculative results yet.
	private String getSpeculatedJ5_32() {
		String expected =
		//@formatter:off
			"NOT YET DETERMINED";
		//@formatter:on
		return expected;
	}

	//@formatter:off
	/*
	struct J5 : virtual GG2, virtual GG3, I3, GG1, I, A {
	  int j51;
	  void j5f();
	};

	class J5	size(164):
		+---
	 0	| +--- (base class I3)
	 0	| | +--- (base class G1)
	 0	| | | {vbptr}
	 8	| | | g11
	  	| | | <alignment member> (size=4)
		| | +---
	16	| | +--- (base class H1)
	16	| | | {vbptr}
	24	| | | h11
	  	| | | <alignment member> (size=4)
		| | +---
	32	| | i31
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class GG1)
	40	| | {vbptr}
	48	| | gg11
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	56	| +--- (base class I)
	56	| | +--- (base class G)
	56	| | | {vbptr}
	64	| | | g1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	72	| | +--- (base class H)
	72	| | | {vbptr}
	80	| | | h1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	88	| | i1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	96	| +--- (base class A)
	96	| | c
	  	| | <alignment member> (size=3)
	100	| | i
		| +---
	104	| j51
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC2)
	112	| cc21
		+---
		+--- (virtual base GG2)
	120	| {vbptr}
	128	| gg21
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base GG3)
	136	| {vbptr}
	144	| gg31
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	152	| c1
		+---
		+--- (virtual base E)
	156	| e1
		+---
		+--- (virtual base CC1)
	160	| cc11
		+---

	J5::$vbtable@G1@:
	 0	| 0
	 1	| 152 (J5d(G1+0)C)
	 2	| 156 (J5d(G1+0)E)
	 3	| 112 (J5d(J5+0)CC2)
	 4	| 120 (J5d(J5+0)GG2)
	 5	| 136 (J5d(J5+0)GG3)
	 6	| 160 (J5d(J5+0)CC1)

	J5::$vbtable@H1@:
	 0	| 0
	 1	| 140 (J5d(H1+0)E)
	 2	| 136 (J5d(H1+0)C)

	J5::$vbtable@GG1@:
	 0	| 0
	 1	| 120 (J5d(GG1+0)CC1)

	J5::$vbtable@G@:
	 0	| 0
	 1	| 96 (J5d(G+0)C)

	J5::$vbtable@H@:
	 0	| 0
	 1	| 80 (J5d(H+0)C)

	J5::$vbtable@GG2@:
	 0	| 0
	 1	| -8 (J5d(GG2+0)CC2)

	J5::$vbtable@GG3@:
	 0	| 0
	 1	| -24 (J5d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC2     112       0      12 0
	             GG2     120       0      16 0
	             GG3     136       0      20 0
	               C     152       0       4 0
	               E     156       0       8 0
	             CC1     160       0      24 0
	 */
	//@formatter:on
	private String getExpectedJ5_64() {
		String expected =
		//@formatter:off
			"""
			/J5
			pack()
			Structure J5 {
			   0   J5   112      "Self Base"
			   112   CC2   4      "Virtual Base"
			   120   GG2   16      "Virtual Base"
			   136   GG3   16      "Virtual Base"
			   152   C   4      "Virtual Base"
			   156   E   4      "Virtual Base"
			   160   CC1   4      "Virtual Base"
			}
			Length: 168 Alignment: 8
			/A
			pack()
			Structure A {
			   0   undefined1   1   c   ""
			   4   undefined4   4   i   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   undefined4   4   c1   ""
			}
			Length: 4 Alignment: 4
			/CC1
			pack()
			Structure CC1 {
			   0   undefined4   4   cc11   ""
			}
			Length: 4 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   undefined4   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   g11   ""
			}
			Length: 16 Alignment: 8
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg11   ""
			}
			Length: 16 Alignment: 8
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg21   ""
			}
			Length: 16 Alignment: 8
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg31   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I/!internal/I
			pack()
			Structure I {
			   0   G   16      "Base"
			   16   H   16      "Base"
			   32   undefined4   4   i1   ""
			}
			Length: 40 Alignment: 8
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   16      "Base"
			   16   H1   16      "Base"
			   32   undefined4   4   i31   ""
			}
			Length: 40 Alignment: 8
			/J5/!internal/J5
			pack()
			Structure J5 {
			   0   I3   40      "Base"
			   40   GG1   16      "Base"
			   56   I   40      "Base"
			   96   A   8      "Base"
			   104   undefined4   4   j51   ""
			}
			Length: 112 Alignment: 8""";

		//@formatter:on
		return expected;
	}

	// TODO: Need to work on layout algorithm... believe we can do better, but don't have
	//  a decision on the best speculative results yet.
	private String getSpeculatedJ5_64() {
		String expected =
		//@formatter:off
			"NOT YET DETERMINED";
		//@formatter:on
		return expected;
	}

	//==============================================================================================
	/*
	 * struct J6 : virtual GG4, virtual GG3, A { //GG4 has no members
	 *    int j61;
	 *	  void j6f();
	 * };
	 */
	static CppCompositeType createJ6_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType A_struct, CppCompositeType GG4_struct, CppCompositeType GG3_struct,
			CppCompositeType CC2_struct, CppCompositeType CC3_struct) {
		return is64Bit
				? createJ6_struct64(vxtManager, A_struct, GG4_struct, GG3_struct, CC2_struct,
					CC3_struct)
				: createJ6_struct32(vxtManager, A_struct, GG4_struct, GG3_struct, CC2_struct,
					CC3_struct);
	}

	static CppCompositeType createJ6_struct32(VxtManager vxtManager, CppCompositeType A_struct,
			CppCompositeType GG4_struct, CppCompositeType GG3_struct, CppCompositeType CC2_struct,
			CppCompositeType CC3_struct) {
		try {
			CppCompositeType J6_struct = createStruct32("J6", 36);
			J6_struct.addDirectBaseClass(A_struct, 0);
			J6_struct.addDirectVirtualBaseClass(GG4_struct, 8, vbtptr32, 2);
			J6_struct.addDirectVirtualBaseClass(GG3_struct, 8, vbtptr32, 4);
			J6_struct.addIndirectVirtualBaseClass(CC3_struct, 8, vbtptr32, 1);
			J6_struct.addIndirectVirtualBaseClass(CC2_struct, 8, vbtptr32, 3);
			J6_struct.addMember("j61", u4, false, 12);
			return J6_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ6_struct64(VxtManager vxtManager, CppCompositeType A_struct,
			CppCompositeType GG4_struct, CppCompositeType GG3_struct, CppCompositeType CC2_struct,
			CppCompositeType CC3_struct) {
		try {
			CppCompositeType J6_struct = createStruct64("J6", 64);
			J6_struct.addDirectBaseClass(A_struct, 0);
			J6_struct.addDirectVirtualBaseClass(GG4_struct, 8, vbtptr64, 2);
			J6_struct.addDirectVirtualBaseClass(GG3_struct, 8, vbtptr64, 4);
			J6_struct.addIndirectVirtualBaseClass(CC3_struct, 8, vbtptr64, 1);
			J6_struct.addIndirectVirtualBaseClass(CC2_struct, 8, vbtptr64, 3);
			J6_struct.addMember("j61", u4, false, 16);
			return J6_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//@formatter:off
	/*
	struct J6 : virtual GG4, virtual GG3, A { //GG4 contains CC3, which has no members
	  int j61;
	  void j6f();
	};

	class J6	size(36):
		+---
	 0	| +--- (base class A)
	 0	| | c
	  	| | <alignment member> (size=3)
	 4	| | i
		| +---
	 8	| {vbptr}
	12	| j61
		+---
		+--- (virtual base CC3)
		+---
		+--- (virtual base GG4)
	16	| {vbptr}
	20	| gg41
		+---
		+--- (virtual base CC2)
	24	| cc21
		+---
		+--- (virtual base GG3)
	28	| {vbptr}
	32	| gg31
		+---

	J6::$vbtable@J6@:
	 0	| -8
	 1	| 8 (J6d(J6+8)CC3)
	 2	| 8 (J6d(J6+8)GG4)
	 3	| 16 (J6d(J6+8)CC2)
	 4	| 20 (J6d(J6+8)GG3)

	J6::$vbtable@GG4@:
	 0	| 0
	 1	| 0 (J6d(GG4+0)CC3)

	J6::$vbtable@GG3@:
	 0	| 0
	 1	| -4 (J6d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC3      16       8       4 0
	             GG4      16       8       8 0
	             CC2      24       8      12 0
	             GG3      28       8      16 0
	 */
	//@formatter:on
	private String getExpectedJ6_32() {
		String expected =
		//@formatter:off
			"""
			/J6
			pack()
			Structure J6 {
			   0   J6   16      "Self Base"
			   16   GG4   8      "Virtual Base"
			   24   CC2   4      "Virtual Base and previous (Empty Virtual Base CC3)"
			   28   GG3   8      "Virtual Base"
			}
			Length: 36 Alignment: 4
			/A
			pack()
			Structure A {
			   0   undefined1   1   c   ""
			   4   undefined4   4   i   ""
			}
			Length: 8 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg31   ""
			}
			Length: 8 Alignment: 4
			/GG4/!internal/GG4
			pack()
			Structure GG4 {
			   0   pointer   4   {vbptr}   ""
			   4   undefined4   4   gg41   ""
			}
			Length: 8 Alignment: 4
			/J6/!internal/J6
			pack()
			Structure J6 {
			   0   A   8      "Base"
			   8   pointer   4   {vbptr}   ""
			   12   undefined4   4   j61   ""
			}
			Length: 16 Alignment: 4""";

		//@formatter:on
		return expected;
	}

	// TODO: Need to work on layout algorithm... believe we can do better, but don't have
	//  a decision on the best speculative results yet.
	private String getSpeculatedJ6_32() {
		String expected =
		//@formatter:off
			"NOT YET DETERMINED";
		//@formatter:on
		return expected;
	}

	//@formatter:off
	/*
	struct J6 : virtual GG4, virtual GG3, A { //GG4 contains CC3, which has no members
	  int j61;
	  void j6f();
	};

	class J6	size(64):
		+---
	 0	| +--- (base class A)
	 0	| | c
	  	| | <alignment member> (size=3)
	 4	| | i
		| +---
	 8	| {vbptr}
	16	| j61
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC3)
		+---
		+--- (virtual base GG4)
	24	| {vbptr}
	32	| gg41
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC2)
	40	| cc21
		+---
		+--- (virtual base GG3)
	48	| {vbptr}
	56	| gg31
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---

	J6::$vbtable@J6@:
	 0	| -8
	 1	| 16 (J6d(J6+8)CC3)
	 2	| 16 (J6d(J6+8)GG4)
	 3	| 32 (J6d(J6+8)CC2)
	 4	| 40 (J6d(J6+8)GG3)

	J6::$vbtable@GG4@:
	 0	| 0
	 1	| 0 (J6d(GG4+0)CC3)

	J6::$vbtable@GG3@:
	 0	| 0
	 1	| -8 (J6d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC3      24       8       4 0
	             GG4      24       8       8 0
	             CC2      40       8      12 0
	             GG3      48       8      16 0
	 */
	//@formatter:on
	private String getExpectedJ6_64() {
		String expected =
		//@formatter:off
			"""
			/J6
			pack()
			Structure J6 {
			   0   J6   24      "Self Base"
			   24   GG4   16      "Virtual Base"
			   40   CC2   4      "Virtual Base and previous (Empty Virtual Base CC3)"
			   48   GG3   16      "Virtual Base"
			}
			Length: 64 Alignment: 8
			/A
			pack()
			Structure A {
			   0   undefined1   1   c   ""
			   4   undefined4   4   i   ""
			}
			Length: 8 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   undefined4   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg31   ""
			}
			Length: 16 Alignment: 8
			/GG4/!internal/GG4
			pack()
			Structure GG4 {
			   0   pointer   8   {vbptr}   ""
			   8   undefined4   4   gg41   ""
			}
			Length: 16 Alignment: 8
			/J6/!internal/J6
			pack()
			Structure J6 {
			   0   A   8      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   undefined4   4   j61   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	// TODO: Need to work on layout algorithm... believe we can do better, but don't have
	//  a decision on the best speculative results yet.
	private String getSpeculatedJ6_64() {
		String expected =
		//@formatter:off
			"NOT YET DETERMINED";
		//@formatter:on
		return expected;
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================

	/**
	 * Test classes using 32-bit organization and in-memory vbt
	 * @throws Exception upon error
	 */
	@Test
	public void test_32bit_vbt() throws Exception {
		boolean is64Bit = false;
		MyTestDummyDataTypeManager dtm = dtm32;
		VxtManager vxtManager = msftVxtManager32;
		List<String> expectedResults = new ArrayList<>();
		expectedResults.add(getExpectedA_32());
		expectedResults.add(getExpectedC_32());
		expectedResults.add(getExpectedCC1_32());
		expectedResults.add(getExpectedCC2_32());
		expectedResults.add(getExpectedCC3_32());
		expectedResults.add(getExpectedD_32());
		expectedResults.add(getExpectedE_32());
		expectedResults.add(getExpectedF_32());
		expectedResults.add(getExpectedG_32());
		expectedResults.add(getExpectedH_32());
		expectedResults.add(getExpectedG1_32());
		expectedResults.add(getExpectedH1_32());
		expectedResults.add(getExpectedGG1_32());
		expectedResults.add(getExpectedGG2_32());
		expectedResults.add(getExpectedGG3_32());
		expectedResults.add(getExpectedGG4_32());
		expectedResults.add(getExpectedI_32());
		expectedResults.add(getExpectedI1_32());
		expectedResults.add(getExpectedI2_32());
		expectedResults.add(getExpectedI3_32());
		expectedResults.add(getExpectedI4_32());
		expectedResults.add(getExpectedI5_32());
		expectedResults.add(getExpectedJ1_32());
		expectedResults.add(getExpectedJ2_32());
		expectedResults.add(getExpectedJ3_32());
		expectedResults.add(getExpectedJ4_32());
		expectedResults.add(getExpectedJ5_32());
		expectedResults.add(getExpectedJ6_32());

		dtm.clearMap();
		createAndTestStructures(is64Bit, dtm, vxtManager, expectedResults);
	}

	/**
	 * Test classes using 32-bit organization and generic vbt (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void test_32bit_speculative() throws Exception {
		boolean is64Bit = false;
		MyTestDummyDataTypeManager dtm = dtm32;
		VxtManager vxtManager = vxtManager32;
		List<String> expectedResults = new ArrayList<>();
		expectedResults.add(getSpeculatedA_32());
		expectedResults.add(getSpeculatedC_32());
		expectedResults.add(getSpeculatedCC1_32());
		expectedResults.add(getSpeculatedCC2_32());
		expectedResults.add(getSpeculatedCC3_32());
		expectedResults.add(getSpeculatedD_32());
		expectedResults.add(getSpeculatedE_32());
		expectedResults.add(getSpeculatedF_32());
		expectedResults.add(getSpeculatedG_32());
		expectedResults.add(getSpeculatedH_32());
		expectedResults.add(getSpeculatedG1_32());
		expectedResults.add(getSpeculatedH1_32());
		expectedResults.add(getSpeculatedGG1_32());
		expectedResults.add(getSpeculatedGG2_32());
		expectedResults.add(getSpeculatedGG3_32());
		expectedResults.add(getSpeculatedGG4_32());
		expectedResults.add(getSpeculatedI_32());
		expectedResults.add(getSpeculatedI1_32());
		expectedResults.add(getSpeculatedI2_32());
		expectedResults.add(getSpeculatedI3_32());
		expectedResults.add(getSpeculatedI4_32());
		expectedResults.add(getSpeculatedI5_32());
		expectedResults.add(getSpeculatedJ1_32());
		expectedResults.add(getSpeculatedJ2_32());
		expectedResults.add(getSpeculatedJ3_32());
		expectedResults.add(getSpeculatedJ4_32());
		expectedResults.add(getSpeculatedJ5_32());
		expectedResults.add(getSpeculatedJ6_32());

		dtm.clearMap();
		createAndTestStructures(is64Bit, dtm, vxtManager, expectedResults);
	}

	/**
	 * Test classes using 64-bit organization and in-memory vbt
	 * @throws Exception upon error
	 */
	@Test
	public void test_64bit_vbt() throws Exception {
		boolean is64Bit = true;
		MyTestDummyDataTypeManager dtm = dtm64;
		VxtManager vxtManager = msftVxtManager64;
		List<String> expectedResults = new ArrayList<>();
		expectedResults.add(getExpectedA_64());
		expectedResults.add(getExpectedC_64());
		expectedResults.add(getExpectedCC1_64());
		expectedResults.add(getExpectedCC2_64());
		expectedResults.add(getExpectedCC3_64());
		expectedResults.add(getExpectedD_64());
		expectedResults.add(getExpectedE_64());
		expectedResults.add(getExpectedF_64());
		expectedResults.add(getExpectedG_64());
		expectedResults.add(getExpectedH_64());
		expectedResults.add(getExpectedG1_64());
		expectedResults.add(getExpectedH1_64());
		expectedResults.add(getExpectedGG1_64());
		expectedResults.add(getExpectedGG2_64());
		expectedResults.add(getExpectedGG3_64());
		expectedResults.add(getExpectedGG4_64());
		expectedResults.add(getExpectedI_64());
		expectedResults.add(getExpectedI1_64());
		expectedResults.add(getExpectedI2_64());
		expectedResults.add(getExpectedI3_64());
		expectedResults.add(getExpectedI4_64());
		expectedResults.add(getExpectedI5_64());
		expectedResults.add(getExpectedJ1_64());
		expectedResults.add(getExpectedJ2_64());
		expectedResults.add(getExpectedJ3_64());
		expectedResults.add(getExpectedJ4_64());
		expectedResults.add(getExpectedJ5_64());
		expectedResults.add(getExpectedJ6_64());

		dtm.clearMap();
		createAndTestStructures(is64Bit, dtm, vxtManager, expectedResults);
	}

	/**
	 * Test classes using 64-bit organization and generic vbt (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void test_64bit_speculative() throws Exception {
		boolean is64Bit = true;
		MyTestDummyDataTypeManager dtm = dtm64;
		VxtManager vxtManager = vxtManager64;
		List<String> expectedResults = new ArrayList<>();
		expectedResults.add(getSpeculatedA_64());
		expectedResults.add(getSpeculatedC_64());
		expectedResults.add(getSpeculatedCC1_64());
		expectedResults.add(getSpeculatedCC2_64());
		expectedResults.add(getSpeculatedCC3_64());
		expectedResults.add(getSpeculatedD_64());
		expectedResults.add(getSpeculatedE_64());
		expectedResults.add(getSpeculatedF_64());
		expectedResults.add(getSpeculatedG_64());
		expectedResults.add(getSpeculatedH_64());
		expectedResults.add(getSpeculatedG1_64());
		expectedResults.add(getSpeculatedH1_64());
		expectedResults.add(getSpeculatedGG1_64());
		expectedResults.add(getSpeculatedGG2_64());
		expectedResults.add(getSpeculatedGG3_64());
		expectedResults.add(getSpeculatedGG4_64());
		expectedResults.add(getSpeculatedI_64());
		expectedResults.add(getSpeculatedI1_64());
		expectedResults.add(getSpeculatedI2_64());
		expectedResults.add(getSpeculatedI3_64());
		expectedResults.add(getSpeculatedI4_64());
		expectedResults.add(getSpeculatedI5_64());
		expectedResults.add(getSpeculatedJ1_64());
		expectedResults.add(getSpeculatedJ2_64());
		expectedResults.add(getSpeculatedJ3_64());
		expectedResults.add(getSpeculatedJ4_64());
		expectedResults.add(getSpeculatedJ5_64());
		expectedResults.add(getSpeculatedJ6_64());

		dtm.clearMap();
		createAndTestStructures(is64Bit, dtm, vxtManager, expectedResults);
	}

	private void createAndTestStructures(boolean is64Bit, DataTypeManager dtm,
			VxtManager vxtManager, List<String> expectedResults) throws Exception {

		Iterator<String> iter = expectedResults.iterator();
		String expected;
		Composite composite;

		expected = iter.next();
		CppCompositeType A_struct = createA_struct(vxtManager, is64Bit);
		A_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(A_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType C_struct = createC_struct(vxtManager, is64Bit);
		C_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(C_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType CC1_struct = createCC1_struct(vxtManager, is64Bit);
		CC1_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(CC1_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType CC2_struct = createCC2_struct(vxtManager, is64Bit);
		CC2_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(CC2_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType CC3_struct = createCC3_struct(vxtManager, is64Bit);
		CC3_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(CC3_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType D_struct = createD_struct(vxtManager, is64Bit, C_struct);
		D_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(D_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType E_struct = createE_struct(vxtManager, is64Bit);
		E_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(E_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType F_struct = createF_struct(vxtManager, is64Bit, C_struct, E_struct);
		F_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(F_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType G_struct = createG_struct(vxtManager, is64Bit, C_struct);
		G_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(G_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType H_struct = createH_struct(vxtManager, is64Bit, C_struct);
		H_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(H_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType G1_struct = createG1_struct(vxtManager, is64Bit, C_struct, E_struct);
		G1_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(G1_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType H1_struct = createH1_struct(vxtManager, is64Bit, E_struct, C_struct);
		H1_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(H1_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType GG1_struct = createGG1_struct(vxtManager, is64Bit, CC1_struct);
		GG1_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(GG1_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType GG2_struct = createGG2_struct(vxtManager, is64Bit, CC2_struct);
		GG2_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(GG2_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType GG3_struct = createGG3_struct(vxtManager, is64Bit, CC2_struct);
		GG3_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(GG3_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType GG4_struct = createGG4_struct(vxtManager, is64Bit, CC3_struct);
		GG4_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(GG4_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType I_struct =
			createI_struct(vxtManager, is64Bit, G_struct, H_struct, C_struct);
		I_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(I_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType I1_struct =
			createI1_struct(vxtManager, is64Bit, G1_struct, H_struct, C_struct, E_struct);
		I1_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(I1_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType I2_struct =
			createI2_struct(vxtManager, is64Bit, G_struct, H1_struct, C_struct, E_struct);
		I2_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(I2_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType I3_struct =
			createI3_struct(vxtManager, is64Bit, G1_struct, H1_struct, E_struct, C_struct);
		I3_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(I3_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType I4_struct =
			createI4_struct(vxtManager, is64Bit, G1_struct, E_struct, C_struct);
		I4_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(I4_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType I5_struct =
			createI5_struct(vxtManager, is64Bit, G1_struct, E_struct, C_struct);
		I5_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(I5_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType J1_struct =
			createJ1_struct(vxtManager, is64Bit, I1_struct, I2_struct, E_struct, C_struct);
		J1_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(J1_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType J2_struct =
			createJ2_struct(vxtManager, is64Bit, I2_struct, I1_struct, C_struct, E_struct);
		J2_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(J2_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType J3_struct = createJ3_struct(vxtManager, is64Bit, I2_struct, I1_struct,
			A_struct, C_struct, E_struct);
		J3_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(J3_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		CppCompositeType J4_struct = createJ4_struct(vxtManager, is64Bit, I3_struct, GG1_struct,
			I_struct, A_struct, GG2_struct, GG3_struct, C_struct, E_struct, CC1_struct, CC2_struct);
		J4_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
		composite = (Composite) dtm.resolve(J4_struct.getComposite(), null);
		CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);

		expected = iter.next();
		if (!expected.equals("NOT YET DETERMINED")) {
			CppCompositeType J5_struct = createJ5_struct(vxtManager, is64Bit, I3_struct, GG1_struct,
				I_struct, A_struct, GG2_struct, GG3_struct, C_struct, E_struct, CC1_struct,
				CC2_struct);
			J5_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
			composite = (Composite) dtm.resolve(J5_struct.getComposite(), null);
			CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);
		}

		expected = iter.next();
		if (!expected.equals("NOT YET DETERMINED")) {
			CppCompositeType J6_struct = createJ6_struct(vxtManager, is64Bit, A_struct, GG4_struct,
				GG3_struct, CC2_struct, CC3_struct);
			J6_struct.createLayout(classLayoutChoice, vxtManager, TaskMonitor.DUMMY);
			composite = (Composite) dtm.resolve(J6_struct.getComposite(), null);
			CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);
		}

	}

	//==============================================================================================
	//==============================================================================================

	/**
	 * Test struct J5 - 32 - syntactics
	 * @throws Exception upon error
	 */
//	@Test
	@Ignore
	public void testJ5_32_syntactic_layout() throws Exception {
//		SyntacticClass structJ5 = createSyntacticStructJ5(MsftVxtManager32);
		// TODO: determine if we need a builder that inputs a SyntacticClass along with a
		// data type manager (w/ data organization), along with layout options for creating
		// data type (/class).
		//structJ5.createLayoutFromSyntacticDescription(MsftVxtManager32, TaskMonitor.DUMMY);

		//
		//Composite composite = structJ5.getComposite();
		//CompositeTestUtils.assertExpectedComposite(this, getExpectedJ5_32(), composite, true);
	}

}
