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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

/**
 * Unit tests for the {@link CppCompositeType}.
 */
public class CppCompositeTypeTest extends AbstractGenericTest {

	private static DataTypeManager dtm32;
	private static DataTypeManager dtm64;
	private static Memory memory32;
	private static Memory memory64;
	private static Map<String, Address> addressByMangledName32;
	private static Map<String, Address> addressByMangledName64;
	private static DataType vbptr32;
	private static DataType vbptr64;
	private static PdbVbtManager pdbVbtManager32;
	private static PdbVbtManager pdbVbtManager64;
	private static VbtManager vbtManager32;
	private static VbtManager vbtManager64;
	// Note: Currently all test have expected results based on up the COMPLEX layout.
	private static ObjectOrientedClassLayout classLayoutChoice =
		ObjectOrientedClassLayout.COMPLEX;

	static {
		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl();
		bitFieldPacking.setUseMSConvention(true);

		// DataOrganization based on x86-64.cspec
		DataOrganizationImpl dataOrg32 = DataOrganizationImpl.getDefaultOrganization(null);
		dataOrg32.setBigEndian(false);
		dataOrg32.setAbsoluteMaxAlignment(0);
		dataOrg32.setMachineAlignment(2);
		dataOrg32.setDefaultPointerAlignment(4);
		dataOrg32.setPointerSize(4);

		dataOrg32.setSizeAlignment(4, 4);

		dataOrg32.setBitFieldPacking(bitFieldPacking);

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
		// DataOrganization based on x86-64.cspec
		DataOrganizationImpl dataOrg64 = DataOrganizationImpl.getDefaultOrganization(null);
		dataOrg64.setBigEndian(false);
		dataOrg64.setAbsoluteMaxAlignment(0);
		dataOrg64.setMachineAlignment(2);
		dataOrg64.setDefaultPointerAlignment(8);
		dataOrg64.setPointerSize(8);

		dataOrg64.setSizeAlignment(8, 8);

		dataOrg64.setBitFieldPacking(bitFieldPacking);

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
		vbptr32 = new PointerDataType(new IntegerDataType(dtm32));
		vbptr64 = new PointerDataType(new IntegerDataType(dtm64));
		System.out.println("vbptr32 size: " + vbptr32.getLength());
		System.out.println("vbptr64 size: " + vbptr64.getLength());

		createVbTables();

		pdbVbtManager32 = new PdbVbtManager(dtm32, memory32, addressByMangledName32);
		pdbVbtManager64 = new PdbVbtManager(dtm64, memory64, addressByMangledName64);
		vbtManager32 = new VbtManager(dtm32);
		vbtManager64 = new VbtManager(dtm64);
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

//		vbtSymbols.add("??_8GG4@@7B@");
//		preparer32.addIntegers(new int[] { 0, 8});
//		preparer64.addIntegers(new int[] { 0, 16});

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
		return original.replace("(Virtual Base", "((Speculative Placement) Virtual Base");
	}

	private static CppCompositeType createStruct32(String name, int size) {
		Composite composite = new StructureDataType(CategoryPath.ROOT, name, 0, dtm32);
		String mangledName = createMangledName(name, CppCompositeType.Type.STRUCT);
		return CppCompositeType.createCppStructType(composite, name, mangledName, size);
	}

	private static CppCompositeType createStruct64(String name, int size) {
		Composite composite = new StructureDataType(CategoryPath.ROOT, name, 0, dtm64);
		String mangledName = createMangledName(name, CppCompositeType.Type.STRUCT);
		return CppCompositeType.createCppStructType(composite, name, mangledName, 0);
	}

	private static String createMangledName(String className, CppCompositeType.Type type) {
		StringBuilder builder = new StringBuilder();
		builder.append(".?A");
		switch (type) {
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
				String msg = "Cannot handle type during testing" + type;
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

	// Note: the problem with using the following static variables is that the process of
	//  processing any one requires the parents already be processed (the dependency issue)
	//  We could use the static version for parents in the create<X>_struct32() methods.
//	private static CppCompositeType A;
//	private static CppCompositeType C;
//	private static CppCompositeType CC1;
//	private static CppCompositeType CC2;
//	private static CppCompositeType CC3;
//	private static CppCompositeType D;
//	private static CppCompositeType E;
//	private static CppCompositeType F;
//	private static CppCompositeType G;
//	private static CppCompositeType H;
//	private static CppCompositeType G1;
//	private static CppCompositeType H1;
//	private static CppCompositeType GG1;
//	private static CppCompositeType GG2;
//	private static CppCompositeType GG3;
//	private static CppCompositeType GG4;
//	private static CppCompositeType I;
//	private static CppCompositeType I1;
//	private static CppCompositeType I2;
//	private static CppCompositeType I3;
//	private static CppCompositeType I4;
//	private static CppCompositeType I5;
//	private static CppCompositeType J1;
//	private static CppCompositeType J2;
//	private static CppCompositeType J3;
//	private static CppCompositeType J4;
//	private static CppCompositeType J5;
//	private static CppCompositeType J6;
//	static {
//		A = createA_struct32();
//		C = createC_struct32();
//		CC1 = createCC1_struct32();
//		CC2 = createCC2_struct32();
//		CC3 = createCC3_struct32();
//		D = createD_struct32(C);
//		E = createE_struct32();
//		F = createF_struct32(C, E);
//		G = createG_struct32(C);
//		H = createH_struct32(C);
//		G1 = createG1_struct32(C, E);
//		H1 = createH1_struct32(E, C);
//		GG1 = createGG1_struct32(CC1);
//		GG2 = createGG2_struct32(CC2);
//		GG3 = createGG3_struct32(CC2);
//		GG4 = createGG4_struct32(CC3);
//		I = createI_struct32(G, H, C);
//		I1 = createI1_struct32(G1, H, C, E);
//		I2 = createI2_struct32(G, H1, C, E);
//		I3 = createI3_struct32(G1, H1, E, C);
//		I4 = createI4_struct32(G1, E, C);
//		I5 = createI5_struct32(G1, E, C); // check this and I4...TODO
//		J1 = createJ1_struct32(I1, I2, E, C);
//		J2 = createJ2_struct32(I2, I1, C, E);
//		J3 = createJ3_struct32(I2, I1, A, C, E);
//		J4 = createJ4_struct32(I3, GG1, I, A, GG2, GG3, C, E, CC1, CC2);
//		J5 = createJ5_struct32(I3, GG1, I, A, GG2, GG3, C, E, CC1, CC2);
//		J6 = createJ6_struct32(A, GG4, GG3, CC2, CC3);
//	}

	//==============================================================================================
	/*
	 * struct A {
	 *    char c;
	 *    int i;
	 * };
	 */
	static CppCompositeType createA_syntactic_struct32(VbtManager vbtManager) {
		CppCompositeType A_struct = createStruct32("A", 0);
		A_struct.addMember("c", u1, false, 0);
		A_struct.addMember("i", u4, false, 0);
		return A_struct;
	}

	static CppCompositeType createA_struct32(VbtManager vbtManager) {
		CppCompositeType A_struct = createStruct32("A", 8);
		A_struct.addMember("c", u1, false, 0);
		A_struct.addMember("i", u4, false, 4);
		return A_struct;
	}

	//==============================================================================================
	/*
	 * struct A {
	 *    char c;
	 *    int i;
	 * };
	 */
	static CppCompositeType createA_struct64(VbtManager vbtManager) {
		CppCompositeType A_struct = createStruct64("A", 8);
		A_struct.addMember("c", u1, false, 0);
		A_struct.addMember("i", u4, false, 4);
		return A_struct;
	}

	//==============================================================================================
	/*
	 * struct C {
	 *    int c1;
	 *    void cf();
	 * };
	 */
	static CppCompositeType createC_syntactic_struct32(VbtManager vbtManager) {
		CppCompositeType C_struct = createStruct32("C", 0);
		C_struct.addMember("c1", u4, false, 0);
		return C_struct;
	}

	static CppCompositeType createC_struct32(VbtManager vbtManager) {
		CppCompositeType C_struct = createStruct32("C", 4);
		C_struct.addMember("c1", u4, false, 0);
		return C_struct;
	}

	//==============================================================================================
	/*
	 * struct C {
	 *    int c1;
	 *    void cf();
	 * };
	 */
	static CppCompositeType createC_struct64(VbtManager vbtManager) {
		CppCompositeType C_struct = createStruct64("C", 4);
		C_struct.addMember("c1", u4, false, 0);
		return C_struct;
	}

	//==============================================================================================
	/*
	 * struct CC1 {
	 *    int cc11;
	 *    void cc1f();
	 * };
	 */
	static CppCompositeType createCC1_syntactic_struct32(VbtManager vbtManager) {
		CppCompositeType CC1_struct = createStruct32("CC1", 0);
		CC1_struct.addMember("cc11", u4, false, 0);
		return CC1_struct;
	}

	static CppCompositeType createCC1_struct32(VbtManager vbtManager) {
		CppCompositeType CC1_struct = createStruct32("CC1", 4);
		CC1_struct.addMember("cc11", u4, false, 0);
		return CC1_struct;
	}

	//==============================================================================================
	/*
	 * struct CC1 {
	 *    int cc11;
	 *    void cc1f();
	 * };
	 */
	static CppCompositeType createCC1_struct64(VbtManager vbtManager) {
		CppCompositeType CC1_struct = createStruct64("CC1", 4);
		CC1_struct.addMember("cc11", u4, false, 0);
		return CC1_struct;
	}

	//==============================================================================================
	/*
	 * struct CC2 {
	 *    int cc21;
	 *    void cc2f();
	 * };
	 */
	static CppCompositeType createCC2_syntactic_struct32(VbtManager vbtManager) {
		CppCompositeType CC2_struct = createStruct32("CC2", 0);
		CC2_struct.addMember("cc21", u4, false, 0);
		return CC2_struct;
	}

	static CppCompositeType createCC2_struct32(VbtManager vbtManager) {
		CppCompositeType CC2_struct = createStruct32("CC2", 4);
		CC2_struct.addMember("cc21", u4, false, 0);
		return CC2_struct;
	}

	//==============================================================================================
	/*
	 * struct CC2 {
	 *    int cc21;
	 *    void cc2f();
	 * };
	 */
	static CppCompositeType createCC2_struct64(VbtManager vbtManager) {
		CppCompositeType CC2_struct = createStruct64("CC2", 4);
		CC2_struct.addMember("cc21", u4, false, 0);
		return CC2_struct;
	}

	//==============================================================================================
	/*
	 * struct CC3 {
	 *    void cc3f();
	 * };
	 */
	static CppCompositeType createCC3_struct32(VbtManager vbtManager) {
		CppCompositeType CC3_struct = createStruct32("CC3", 0); //TODO size 1 or 0?
		return CC3_struct;
	}

	//==============================================================================================
	/*
	 * struct CC3 {
	 *    void cc3f();
	 * };
	 */
	static CppCompositeType createCC3_struct64(VbtManager vbtManager) {
		CppCompositeType CC3_struct = createStruct64("CC3", 0); //TODO size 1 or 0?
		return CC3_struct;
	}

	//==============================================================================================
	/*
	 * struct D : C {
	 *    int d1;
	 *    void df();
	 * };
	 */
	static CppCompositeType createD_struct32(VbtManager vbtManager) {
		return createD_struct32(vbtManager, null);
	}

	static CppCompositeType createD_struct32(VbtManager vbtManager, CppCompositeType C_struct) {
		CppCompositeType D_struct = createStruct32("D", 8);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			D_struct.addDirectBaseClass(C_struct, 0);
			D_struct.addMember("d1", u4, false, 4);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return D_struct;
	}

	//==============================================================================================
	/*
	 * struct D : C {
	 *    int d1;
	 *    void df();
	 * };
	 */
	static CppCompositeType createD_struct64(VbtManager vbtManager) {
		return createD_struct64(vbtManager, null);
	}

	static CppCompositeType createD_struct64(VbtManager vbtManager, CppCompositeType C_struct) {
		CppCompositeType D_struct = createStruct64("D", 8);
		try {
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			D_struct.addDirectBaseClass(C_struct, 0);
			D_struct.addMember("d1", u4, false, 4);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return D_struct;
	}

	//==============================================================================================
	/*
	 * struct E {
	 *	  int e1;
	 *	  void ef();
	 *	};
	 */
	static CppCompositeType createE_syntactic_struct32(VbtManager vbtManager) {
		CppCompositeType E_struct = createStruct32("E", 0);
		E_struct.addMember("e1", u4, false, 0);
		return E_struct;
	}

	static CppCompositeType createE_struct32(VbtManager vbtManager) {
		CppCompositeType E_struct = createStruct32("E", 4);
		E_struct.addMember("e1", u4, false, 0);
		return E_struct;
	}

	//==============================================================================================
	/*
	 * struct E {
	 *	  int e1;
	 *	  void ef();
	 *	};
	 */
	static CppCompositeType createE_struct64(VbtManager vbtManager) {
		CppCompositeType E_struct = createStruct64("E", 4);
		E_struct.addMember("e1", u4, false, 0);
		return E_struct;
	}

	//==============================================================================================
	/*
	 * struct F : C, E {
	 *	  int f1;
	 *	  void ff();
	 *	};
	 */
	static CppCompositeType createF_struct32(VbtManager vbtManager) {
		return createF_struct32(vbtManager, null, null);
	}

	static CppCompositeType createF_struct32(VbtManager vbtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		CppCompositeType F_struct = createStruct32("F", 12);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			F_struct.addDirectBaseClass(C_struct, 0);
			F_struct.addDirectBaseClass(E_struct, 4);
			F_struct.addMember("f1", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return F_struct;
	}

	//==============================================================================================
	/*
	 * struct F : C, E {
	 *	  int f1;
	 *	  void ff();
	 *	};
	 */
	static CppCompositeType createF_struct64(VbtManager vbtManager) {
		return createF_struct64(vbtManager, null, null);
	}

	static CppCompositeType createF_struct64(VbtManager vbtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		CppCompositeType F_struct = createStruct64("F", 12);
		try {
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			F_struct.addDirectBaseClass(C_struct, 0);
			F_struct.addDirectBaseClass(E_struct, 4);
			F_struct.addMember("f1", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return F_struct;
	}

	//==============================================================================================
	/*
	 * struct G : virtual C {
	 *	  int g1;
	 *	  void gf();
	 *	};
	 */
	static CppCompositeType createG_syntactic_struct32(VbtManager vbtManager) {
		return createG_syntactic_struct32(vbtManager, null);
	}

	static CppCompositeType createG_syntactic_struct32(VbtManager vbtManager,
			CppCompositeType C_struct) {
		CppCompositeType G_struct = createStruct32("G", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
			}
			G_struct.addVirtualSyntacticBaseClass(C_struct);
			G_struct.addMember("g1", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return G_struct;
	}

	static CppCompositeType createG_struct32(VbtManager vbtManager) {
		return createG_struct32(vbtManager, null);
	}

	static CppCompositeType createG_struct32(VbtManager vbtManager, CppCompositeType C_struct) {
		CppCompositeType G_struct = createStruct32("G", 12);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			G_struct.addDirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			G_struct.addMember("g1", u4, false, 4);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return G_struct;
	}

	//==============================================================================================
	/*
	 * struct G : virtual C {
	 *	  int g1;
	 *	  void gf();
	 *	};
	 */
	static CppCompositeType createG_struct64(VbtManager vbtManager) {
		return createG_struct64(vbtManager, null);
	}

	static CppCompositeType createG_struct64(VbtManager vbtManager, CppCompositeType C_struct) {
		CppCompositeType G_struct = createStruct64("G", 20);
		try {
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			G_struct.addDirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			G_struct.addMember("g1", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return G_struct;
	}

	//==============================================================================================
	/*
	 * struct H : virtual C {
	 *	  int h1;
	 *	  void hf();
	 *	};
	 */
	static CppCompositeType createH_syntactic_struct32(VbtManager vbtManager) {
		return createH_syntactic_struct32(vbtManager, null);
	}

	static CppCompositeType createH_syntactic_struct32(VbtManager vbtManager,
			CppCompositeType C_struct) {
		CppCompositeType H_struct = createStruct32("H", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
			}
			H_struct.addVirtualSyntacticBaseClass(C_struct);
			H_struct.addMember("h1", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return H_struct;
	}

	static CppCompositeType createH_struct32(VbtManager vbtManager) {
		return createH_struct32(vbtManager, null);
	}

	static CppCompositeType createH_struct32(VbtManager vbtManager, CppCompositeType C_struct) {
		CppCompositeType H_struct = createStruct32("H", 12);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			H_struct.addDirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			H_struct.addMember("h1", u4, false, 4);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return H_struct;
	}

	//==============================================================================================
	/*
	 * struct H : virtual C {
	 *	  int h1;
	 *	  void hf();
	 *	};
	 */
	static CppCompositeType createH_struct64(VbtManager vbtManager) {
		return createH_struct64(vbtManager, null);
	}

	static CppCompositeType createH_struct64(VbtManager vbtManager, CppCompositeType C_struct) {
		CppCompositeType H_struct = createStruct64("H", 20);
		try {
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			H_struct.addDirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			H_struct.addMember("h1", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return H_struct;
	}

	//==============================================================================================
	/*
	 * struct G1 : virtual C, virtual E {
	 *	  int g11;
	 *	  void g1f();
	 *	};
	 */
	static CppCompositeType createG1_syntactic_struct32(VbtManager vbtManager) {
		return createG1_syntactic_struct32(vbtManager, null, null);
	}

	static CppCompositeType createG1_syntactic_struct32(VbtManager vbtManager,
			CppCompositeType C_struct, CppCompositeType E_struct) {
		CppCompositeType G1_struct = createStruct32("G1", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
			}
			G1_struct.addVirtualSyntacticBaseClass(C_struct);
			G1_struct.addVirtualSyntacticBaseClass(E_struct);
			G1_struct.addMember("g11", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return G1_struct;
	}

	static CppCompositeType createG1_struct32(VbtManager vbtManager) {
		return createG1_struct32(vbtManager, null, null);
	}

	static CppCompositeType createG1_struct32(VbtManager vbtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		CppCompositeType G1_struct = createStruct32("G1", 16);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			G1_struct.addDirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			G1_struct.addDirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			G1_struct.addMember("g11", u4, false, 4);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return G1_struct;
	}

	//==============================================================================================
	/*
	 * struct G1 : virtual C, virtual E {
	 *	  int g11;
	 *	  void g1f();
	 *	};
	 */
	static CppCompositeType createG1_struct64(VbtManager vbtManager) {
		return createG1_struct64(vbtManager, null, null);
	}

	static CppCompositeType createG1_struct64(VbtManager vbtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		CppCompositeType G1_struct = createStruct64("G1", 24);
		try {
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			G1_struct.addDirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			G1_struct.addDirectVirtualBaseClass(E_struct, 0, vbptr64, 2);
			G1_struct.addMember("g11", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return G1_struct;
	}

	//==============================================================================================
	/*
	 * struct H1 : virtual E, virtual C { //order reversed from G1
	 *	  int h11;
	 *	  void h1f();
	 *	};
	 */
	static CppCompositeType createH1_syntactic_struct32(VbtManager vbtManager) {
		return createH1_syntactic_struct32(vbtManager, null, null);
	}

	static CppCompositeType createH1_syntactic_struct32(VbtManager vbtManager,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType H1_struct = createStruct32("H1", 0);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
			}
			H1_struct.addVirtualSyntacticBaseClass(E_struct);
			H1_struct.addVirtualSyntacticBaseClass(C_struct);
			H1_struct.addMember("h11", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return H1_struct;
	}

	static CppCompositeType createH1_struct32(VbtManager vbtManager) {
		return createH1_struct32(vbtManager, null, null);
	}

	static CppCompositeType createH1_struct32(VbtManager vbtManager, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		CppCompositeType H1_struct = createStruct32("H1", 16);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			H1_struct.addDirectVirtualBaseClass(E_struct, 0, vbptr32, 1);
			H1_struct.addDirectVirtualBaseClass(C_struct, 0, vbptr32, 2);
			H1_struct.addMember("h11", u4, false, 4);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return H1_struct;
	}

	//==============================================================================================
	/*
	 * struct H1 : virtual E, virtual C { //order reversed from G1
	 *	  int h11;
	 *	  void h1f();
	 *	};
	 */
	static CppCompositeType createH1_struct64(VbtManager vbtManager) {
		return createH1_struct64(vbtManager, null, null);
	}

	static CppCompositeType createH1_struct64(VbtManager vbtManager, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		CppCompositeType H1_struct = createStruct64("H1", 24);
		try {
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			H1_struct.addDirectVirtualBaseClass(E_struct, 0, vbptr64, 1);
			H1_struct.addDirectVirtualBaseClass(C_struct, 0, vbptr64, 2);
			H1_struct.addMember("h11", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return H1_struct;
	}

	//==============================================================================================
	/*
	 * struct GG1 : virtual CC1 {
	 *	  int gg11;
	 *	  void gg1f();
	 *	};
	 */
	static CppCompositeType createGG1_syntactic_struct32(VbtManager vbtManager) {
		return createGG1_syntactic_struct32(vbtManager, null);
	}

	static CppCompositeType createGG1_syntactic_struct32(VbtManager vbtManager,
			CppCompositeType CC1_struct) {
		CppCompositeType GG1_struct = createStruct32("GG1", 0);
		try {
			if (CC1_struct == null) {
				CC1_struct = createCC1_struct32(vbtManager);
			}
			GG1_struct.addVirtualSyntacticBaseClass(CC1_struct);
			GG1_struct.addMember("gg11", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG1_struct;
	}

	static CppCompositeType createGG1_struct32(VbtManager vbtManager) {
		return createGG1_struct32(vbtManager, null);
	}

	static CppCompositeType createGG1_struct32(VbtManager vbtManager, CppCompositeType CC1_struct) {
		CppCompositeType GG1_struct = createStruct32("GG1", 12);
		try {
			if (CC1_struct == null) {
				CC1_struct = createCC1_struct32(vbtManager);
				CC1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			GG1_struct.addDirectVirtualBaseClass(CC1_struct, 0, vbptr32, 1);
			GG1_struct.addMember("gg11", u4, false, 4);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG1_struct;
	}

	//==============================================================================================
	/*
	 * struct GG1 : virtual CC1 {
	 *	  int gg11;
	 *	  void gg1f();
	 *	};
	 */
	static CppCompositeType createGG1_struct64(VbtManager vbtManager) {
		return createGG1_struct64(vbtManager, null);
	}

	static CppCompositeType createGG1_struct64(VbtManager vbtManager, CppCompositeType CC1_struct) {
		CppCompositeType GG1_struct = createStruct64("GG1", 20);
		try {
			if (CC1_struct == null) {
				CC1_struct = createCC1_struct64(vbtManager);
				CC1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			GG1_struct.addDirectVirtualBaseClass(CC1_struct, 0, vbptr64, 1);
			GG1_struct.addMember("gg11", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG1_struct;
	}

	//==============================================================================================
	/*
	 * struct GG2 : virtual CC2 {
	 *	  int gg21;
	 *	  void gg2f();
	 *	};
	 */
	static CppCompositeType createGG2_syntactic_struct32(VbtManager vbtManager) {
		return createGG2_syntactic_struct32(vbtManager, null);
	}

	static CppCompositeType createGG2_syntactic_struct32(VbtManager vbtManager,
			CppCompositeType CC2_struct) {
		CppCompositeType GG2_struct = createStruct32("GG2", 0);
		try {
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vbtManager);
			}
			GG2_struct.addVirtualSyntacticBaseClass(CC2_struct);
			GG2_struct.addMember("gg21", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG2_struct;
	}

	static CppCompositeType createGG2_struct32(VbtManager vbtManager) {
		return createGG2_struct32(vbtManager, null);
	}

	static CppCompositeType createGG2_struct32(VbtManager vbtManager, CppCompositeType CC2_struct) {
		CppCompositeType GG2_struct = createStruct32("GG2", 12);
		try {
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vbtManager);
				CC2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			GG2_struct.addDirectVirtualBaseClass(CC2_struct, 0, vbptr32, 1);
			GG2_struct.addMember("gg21", u4, false, 4);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG2_struct;
	}

	//==============================================================================================
	/*
	 * struct GG2 : virtual CC2 {
	 *	  int gg21;
	 *	  void gg2f();
	 *	};
	 */
	static CppCompositeType createGG2_struct64(VbtManager vbtManager) {
		return createGG2_struct64(vbtManager, null);
	}

	static CppCompositeType createGG2_struct64(VbtManager vbtManager, CppCompositeType CC2_struct) {
		CppCompositeType GG2_struct = createStruct64("GG2", 20);
		try {
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct64(vbtManager);
				CC2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			GG2_struct.addDirectVirtualBaseClass(CC2_struct, 0, vbptr64, 1);
			GG2_struct.addMember("gg21", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG2_struct;
	}

	//==============================================================================================
	/*
	 * struct GG3 : virtual CC2 {
	 *	  int gg31;
	 *	  void gg3f();
	 *	};
	 */
	static CppCompositeType createGG3_syntactic_struct32(VbtManager vbtManager) {
		return createGG3_syntactic_struct32(vbtManager, null);
	}

	static CppCompositeType createGG3_syntactic_struct32(VbtManager vbtManager,
			CppCompositeType CC2_struct) {
		CppCompositeType GG3_struct = createStruct32("GG3", 0);
		try {
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vbtManager);
			}
			GG3_struct.addVirtualSyntacticBaseClass(CC2_struct);
			GG3_struct.addMember("gg31", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG3_struct;
	}

	static CppCompositeType createGG3_struct32(VbtManager vbtManager) {
		return createGG3_struct32(vbtManager, null);
	}

	static CppCompositeType createGG3_struct32(VbtManager vbtManager, CppCompositeType CC2_struct) {
		CppCompositeType GG3_struct = createStruct32("GG3", 12);
		try {
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vbtManager);
				CC2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			GG3_struct.addDirectVirtualBaseClass(CC2_struct, 0, vbptr32, 1);
			GG3_struct.addMember("gg31", u4, false, 4);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG3_struct;
	}

	//==============================================================================================
	/*
	 * struct GG3 : virtual CC2 {
	 *	  int gg31;
	 *	  void gg3f();
	 *	};
	 */
	static CppCompositeType createGG3_struct64(VbtManager vbtManager) {
		return createGG3_struct64(vbtManager, null);
	}

	static CppCompositeType createGG3_struct64(VbtManager vbtManager, CppCompositeType CC2_struct) {
		CppCompositeType GG3_struct = createStruct64("GG3", 20);
		try {
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct64(vbtManager);
				CC2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			GG3_struct.addDirectVirtualBaseClass(CC2_struct, 0, vbptr64, 1);
			GG3_struct.addMember("gg31", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG3_struct;
	}

	//==============================================================================================
	/*
	 * struct GG4 : virtual CC3 {
	 *	  int gg41;
	 *	  void gg5f();
	 *	};
	 */
	static CppCompositeType createGG4_struct32(VbtManager vbtManager) {
		return createGG4_struct32(vbtManager, null);
	}

	static CppCompositeType createGG4_struct32(VbtManager vbtManager, CppCompositeType CC3_struct) {
		CppCompositeType GG4_struct = createStruct32("GG4", 8);
		try {
			if (CC3_struct == null) {
				CC3_struct = createCC3_struct32(vbtManager);
				CC3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			GG4_struct.addDirectVirtualBaseClass(CC3_struct, 0, vbptr32, 1);
			GG4_struct.addMember("gg41", u4, false, 4);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG4_struct;
	}

	//==============================================================================================
	/*
	 * struct GG4 : virtual CC3 {
	 *	  int gg41;
	 *	  void gg5f();
	 *	};
	 */
	static CppCompositeType createGG4_struct64(VbtManager vbtManager) {
		return createGG4_struct64(vbtManager, null);
	}

	static CppCompositeType createGG4_struct64(VbtManager vbtManager, CppCompositeType CC3_struct) {
		CppCompositeType GG4_struct = createStruct64("GG4", 16);
		try {
			if (CC3_struct == null) {
				CC3_struct = createCC3_struct64(vbtManager);
				CC3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			GG4_struct.addDirectVirtualBaseClass(CC3_struct, 0, vbptr64, 1);
			GG4_struct.addMember("gg41", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG4_struct;
	}

	//==============================================================================================
	/*
	 * struct I : G, H {
	 *	  int i1;
	 *	  void _if();
	 *	};
	 */
	static CppCompositeType createI_syntactic_struct32(VbtManager vbtManager) {
		return createI_syntactic_struct32(vbtManager, null, null, null);
	}

	static CppCompositeType createI_syntactic_struct32(VbtManager vbtManager,
			CppCompositeType G_struct, CppCompositeType H_struct, CppCompositeType C_struct) {
		CppCompositeType I_struct = createStruct32("I", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
			}
			// Could be problem if only one of G or H is null: won't have same C.
			if (G_struct == null) {
				G_struct = createG_struct32(vbtManager, C_struct);
			}
			if (H_struct == null) {
				H_struct = createH_struct32(vbtManager, C_struct);
			}
			I_struct.addDirectSyntacticBaseClass(G_struct);
			I_struct.addDirectSyntacticBaseClass(H_struct);
			I_struct.addMember("i1", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I_struct;
	}

	static CppCompositeType createI_struct32(VbtManager vbtManager) {
		return createI_struct32(vbtManager, null, null, null);
	}

	static CppCompositeType createI_struct32(VbtManager vbtManager, CppCompositeType G_struct,
			CppCompositeType H_struct, CppCompositeType C_struct) {
		CppCompositeType I_struct = createStruct32("I", 24);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			// Could be problem if only one of G or H is null: won't have same C.
			if (G_struct == null) {
				G_struct = createG_struct32(vbtManager, C_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (H_struct == null) {
				H_struct = createH_struct32(vbtManager, C_struct);
				H_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			I_struct.addDirectBaseClass(G_struct, 0);
			I_struct.addDirectBaseClass(H_struct, 8);
			I_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			I_struct.addMember("i1", u4, false, 16);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I_struct;
	}

	//==============================================================================================
	/*
	 * struct I : G, H {
	 *	  int i1;
	 *	  void _if();
	 *	};
	 */
	static CppCompositeType createI_struct64(VbtManager vbtManager) {
		return createI_struct64(vbtManager, null, null, null);
	}

	static CppCompositeType createI_struct64(VbtManager vbtManager, CppCompositeType G_struct,
			CppCompositeType H_struct, CppCompositeType C_struct) {
		CppCompositeType I_struct = createStruct64("I", 44);
		try {
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			// Could be problem if only one of G or H is null: won't have same C.
			if (G_struct == null) {
				G_struct = createG_struct64(vbtManager, C_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (H_struct == null) {
				H_struct = createH_struct64(vbtManager, C_struct);
				H_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			I_struct.addDirectBaseClass(G_struct, 0);
			I_struct.addDirectBaseClass(H_struct, 16);
			I_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			I_struct.addMember("i1", u4, false, 32);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I_struct;
	}

	//==============================================================================================
	/*
	 * struct I1 : G1, H {
	 *	  int i11;
	 *	  void _i1f();
	 *	};
	 */
	static CppCompositeType createI1_struct32(VbtManager vbtManager) {
		return createI1_struct32(vbtManager, null, null, null, null);
	}

	static CppCompositeType createI1_struct32(VbtManager vbtManager, CppCompositeType G1_struct,
			CppCompositeType H_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		CppCompositeType I1_struct = createStruct32("I1", 28);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct32(vbtManager, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (H_struct == null) {
				H_struct = createH_struct32(vbtManager, C_struct);
				H_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			I1_struct.addDirectBaseClass(G1_struct, 0);
			I1_struct.addDirectBaseClass(H_struct, 8);
			I1_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			I1_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			I1_struct.addMember("i11", u4, false, 16);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I1_struct;
	}

	//==============================================================================================
	/*
	 * struct I1 : G1, H {
	 *	  int i11;
	 *	  void _i1f();
	 *	};
	 */
	static CppCompositeType createI1_struct64(VbtManager vbtManager) {
		return createI1_struct64(vbtManager, null, null, null, null);
	}

	static CppCompositeType createI1_struct64(VbtManager vbtManager, CppCompositeType G1_struct,
			CppCompositeType H_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		CppCompositeType I1_struct = createStruct64("I1", 48);
		try {
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct64(vbtManager, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (H_struct == null) {
				H_struct = createH_struct64(vbtManager, C_struct);
				H_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			I1_struct.addDirectBaseClass(G1_struct, 0);
			I1_struct.addDirectBaseClass(H_struct, 16);
			I1_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			I1_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr64, 2);
			I1_struct.addMember("i11", u4, false, 32);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I1_struct;
	}

	//==============================================================================================
	/*
	 * struct I2 : G, H1 {
	 *	  int i21;
	 *	  void _i2f();
	 *	};
	 */
	static CppCompositeType createI2_struct32(VbtManager vbtManager) {
		return createI2_struct32(vbtManager, null, null, null, null);
	}

	static CppCompositeType createI2_struct32(VbtManager vbtManager, CppCompositeType G_struct,
			CppCompositeType H1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		CppCompositeType I2_struct = createStruct32("I2", 28);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (G_struct == null) {
				G_struct = createG_struct32(vbtManager, C_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (H1_struct == null) {
				H1_struct = createH1_struct32(vbtManager, E_struct, C_struct);
				H1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			I2_struct.addDirectBaseClass(G_struct, 0);
			I2_struct.addDirectBaseClass(H1_struct, 8);
			I2_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			I2_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			I2_struct.addMember("i21", u4, false, 16);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I2_struct;
	}

	//==============================================================================================
	/*
	 * struct I2 : G, H1 {
	 *	  int i21;
	 *	  void _i2f();
	 *	};
	 */
	static CppCompositeType createI2_struct64(VbtManager vbtManager) {
		return createI2_struct64(vbtManager, null, null, null, null);
	}

	static CppCompositeType createI2_struct64(VbtManager vbtManager, CppCompositeType G_struct,
			CppCompositeType H1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		CppCompositeType I2_struct = createStruct64("I2", 48);
		try {
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (G_struct == null) {
				G_struct = createG_struct64(vbtManager, C_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (H1_struct == null) {
				H1_struct = createH1_struct64(vbtManager, E_struct, C_struct);
				H1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			I2_struct.addDirectBaseClass(G_struct, 0);
			I2_struct.addDirectBaseClass(H1_struct, 16);
			I2_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			I2_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr64, 2);
			I2_struct.addMember("i21", u4, false, 32);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I2_struct;
	}

	//==============================================================================================
	/*
	 * struct I3 : G1, H1 {
	 *	  int i31;
	 *	  void _i3f();
	 *	};
	 */
	static CppCompositeType createI3_syntactic_struct32(VbtManager vbtManager) {
		return createI3_syntactic_struct32(vbtManager, null, null, null, null);
	}

	static CppCompositeType createI3_syntactic_struct32(VbtManager vbtManager,
			CppCompositeType G1_struct, CppCompositeType H1_struct, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		CppCompositeType I3_struct = createStruct32("I3", 8);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct32(vbtManager, C_struct, E_struct);
			}
			if (H1_struct == null) {
				H1_struct = createH1_struct32(vbtManager, E_struct, C_struct);
			}
			I3_struct.addDirectSyntacticBaseClass(G1_struct);
			I3_struct.addDirectSyntacticBaseClass(H1_struct);
			I3_struct.addMember("i31", u4, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I3_struct;
	}

	static CppCompositeType createI3_struct32(VbtManager vbtManager) {
		return createI3_struct32(vbtManager, null, null, null, null);
	}

	static CppCompositeType createI3_struct32(VbtManager vbtManager, CppCompositeType G1_struct,
			CppCompositeType H1_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType I3_struct = createStruct32("I3", 28);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct32(vbtManager, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (H1_struct == null) {
				H1_struct = createH1_struct32(vbtManager, E_struct, C_struct);
				H1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			I3_struct.addDirectBaseClass(G1_struct, 0);
			I3_struct.addDirectBaseClass(H1_struct, 8);
			I3_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			I3_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			I3_struct.addMember("i31", u4, false, 16);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I3_struct;
	}

	//==============================================================================================
	/*
	 * struct I3 : G1, H1 {
	 *	  int i31;
	 *	  void _i3f();
	 *	};
	 */
	static CppCompositeType createI3_struct64(VbtManager vbtManager) {
		return createI3_struct64(vbtManager, null, null, null, null);
	}

	static CppCompositeType createI3_struct64(VbtManager vbtManager, CppCompositeType G1_struct,
			CppCompositeType H1_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType I3_struct = createStruct64("I3", 48);
		try {
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct64(vbtManager, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (H1_struct == null) {
				H1_struct = createH1_struct64(vbtManager, E_struct, C_struct);
				H1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			I3_struct.addDirectBaseClass(G1_struct, 0);
			I3_struct.addDirectBaseClass(H1_struct, 16);
			I3_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			I3_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr64, 2);
			I3_struct.addMember("i31", u4, false, 32);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I3_struct;
	}

	//==============================================================================================
	/*
	 * struct I4 : G1, virtual E, virtual C {
	 *	  int i41;
	 *	  void _i4f();
	 *	};
	 */
	static CppCompositeType createI4_struct32(VbtManager vbtManager) {
		return createI4_struct32(vbtManager, null, null, null);
	}

	static CppCompositeType createI4_struct32(VbtManager vbtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType I4_struct = createStruct32("I4", 20);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct32(vbtManager, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			I4_struct.addDirectBaseClass(G1_struct, 0);
			I4_struct.addDirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			I4_struct.addDirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			I4_struct.addMember("i41", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I4_struct;
	}

	//==============================================================================================
	/*
	 * struct I4 : G1, virtual E, virtual C {
	 *	  int i41;
	 *	  void _i4f();
	 *	};
	 */
	static CppCompositeType createI4_struct64(VbtManager vbtManager) {
		return createI4_struct64(vbtManager, null, null, null);
	}

	static CppCompositeType createI4_struct64(VbtManager vbtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType I4_struct = createStruct64("I4", 32);
		try {
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct64(vbtManager, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			I4_struct.addDirectBaseClass(G1_struct, 0);
			I4_struct.addDirectVirtualBaseClass(E_struct, 0, vbptr64, 2);
			I4_struct.addDirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			I4_struct.addMember("i41", u4, false, 16);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I4_struct;
	}

	//==============================================================================================
	/*
	 * struct I5 : virtual E, virtual C, G1 {
	 *	  int i51;
	 *	  void _i5f();
	 *	};
	 */
	static CppCompositeType createI5_struct32(VbtManager vbtManager) {
		return createI5_struct32(vbtManager, null, null, null);
	}

	static CppCompositeType createI5_struct32(VbtManager vbtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType I5_struct = createStruct32("I5", 20);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct32(vbtManager, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			I5_struct.addDirectBaseClass(G1_struct, 0);
			I5_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr32, 2); // check this and I4...TODO
			I5_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			I5_struct.addMember("i51", u4, false, 8);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I5_struct;
	}

	//==============================================================================================
	/*
	 * struct I5 : virtual E, virtual C, G1 {
	 *	  int i51;
	 *	  void _i5f();
	 *	};
	 */
	static CppCompositeType createI5_struct64(VbtManager vbtManager) {
		return createI5_struct64(null, null, null, vbtManager);
	}

	static CppCompositeType createI5_struct64(CppCompositeType G1_struct, CppCompositeType E_struct,
			CppCompositeType C_struct, VbtManager vbtManager) {
		CppCompositeType I5_struct = createStruct64("I5", 32);
		try {
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct64(vbtManager, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			I5_struct.addDirectBaseClass(G1_struct, 0);
			I5_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr64, 2); // check this and I4...TODO
			I5_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			I5_struct.addMember("i51", u4, false, 16);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I5_struct;
	}

	//==============================================================================================
	/*
	 * struct J1 : I1, I2 {
	 *	  int j11;
	 *	  void j1f();
	 *	};
	 */
	static CppCompositeType createJ1_struct32(VbtManager vbtManager) {
		return createJ1_struct32(vbtManager, null, null, null, null);
	}

	static CppCompositeType createJ1_struct32(VbtManager vbtManager, CppCompositeType I1_struct,
			CppCompositeType I2_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType J1_struct = createStruct32("J1", 52);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (I1_struct == null) {
				CppCompositeType G1_struct = createG1_struct32(vbtManager, C_struct, E_struct);
				CppCompositeType H_struct = createH_struct32(vbtManager, C_struct);
				I1_struct = createI1_struct32(vbtManager, G1_struct, H_struct, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				H_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				I1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (I2_struct == null) {
				CppCompositeType G_struct = createG_struct32(vbtManager, C_struct);
				CppCompositeType H1_struct = createH1_struct32(vbtManager, E_struct, C_struct);
				I2_struct = createI2_struct32(vbtManager, G_struct, H1_struct, C_struct, E_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				H1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				I2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			J1_struct.addDirectBaseClass(I1_struct, 0);
			J1_struct.addDirectBaseClass(I2_struct, 20);
			J1_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			J1_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			J1_struct.addMember("j11", u4, false, 40);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J1_struct;
	}

	//==============================================================================================
	/*
	 * struct J1 : I1, I2 {
	 *	  int j11;
	 *	  void j1f();
	 *	};
	 */
	static CppCompositeType createJ1_struct64(VbtManager vbtManager) {
		return createJ1_struct64(null, null, null, null, vbtManager);
	}

	static CppCompositeType createJ1_struct64(CppCompositeType I1_struct,
			CppCompositeType I2_struct, CppCompositeType E_struct, CppCompositeType C_struct,
			VbtManager vbtManager) {
		CppCompositeType J1_struct = createStruct64("J1", 96);
		try {
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (I1_struct == null) {
				CppCompositeType G1_struct = createG1_struct64(vbtManager, C_struct, E_struct);
				CppCompositeType H_struct = createH_struct64(vbtManager, C_struct);
				I1_struct = createI1_struct64(vbtManager, G1_struct, H_struct, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				H_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				I1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (I2_struct == null) {
				CppCompositeType G_struct = createG_struct64(vbtManager, C_struct);
				CppCompositeType H1_struct = createH1_struct64(vbtManager, E_struct, C_struct);
				I2_struct = createI2_struct64(vbtManager, G_struct, H1_struct, C_struct, E_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				H1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				I2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			J1_struct.addDirectBaseClass(I1_struct, 0);
			J1_struct.addDirectBaseClass(I2_struct, 40);
			J1_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			J1_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr64, 2);
			J1_struct.addMember("j11", u4, false, 80);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J1_struct;
	}

	//==============================================================================================
	/*
	 * struct J2 : I2, I1 {
	 *	  int j21;
	 *	  void j2f();
	 *	};
	 */
	static CppCompositeType createJ2_struct32(VbtManager vbtManager) {
		return createJ2_struct32(vbtManager, null, null, null, null);
	}

	static CppCompositeType createJ2_struct32(VbtManager vbtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		CppCompositeType J2_struct = createStruct32("J2", 52);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (I2_struct == null) {
				CppCompositeType G_struct = createG_struct32(vbtManager, C_struct);
				CppCompositeType H1_struct = createH1_struct32(vbtManager, E_struct, C_struct);
				I2_struct = createI2_struct32(vbtManager, G_struct, H1_struct, C_struct, E_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				H1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				I2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (I1_struct == null) {
				CppCompositeType G1_struct = createG1_struct32(vbtManager, C_struct, E_struct);
				CppCompositeType H_struct = createH_struct32(vbtManager, C_struct);
				I1_struct = createI1_struct32(vbtManager, G1_struct, H_struct, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				H_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				I1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			J2_struct.addDirectBaseClass(I2_struct, 0);
			J2_struct.addDirectBaseClass(I1_struct, 20);
			J2_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			J2_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			J2_struct.addMember("j21", u4, false, 40);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J2_struct;
	}

	//==============================================================================================
	/*
	 * struct J2 : I2, I1 {
	 *	  int j21;
	 *	  void j2f();
	 *	};
	 */
	static CppCompositeType createJ2_struct64(VbtManager vbtManager) {
		return createJ2_struct64(vbtManager, null, null, null, null);
	}

	static CppCompositeType createJ2_struct64(VbtManager vbtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		CppCompositeType J2_struct = createStruct64("J2", 96);
		try {
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (I2_struct == null) {
				CppCompositeType G_struct = createG_struct64(vbtManager, C_struct);
				CppCompositeType H1_struct = createH1_struct64(vbtManager, E_struct, C_struct);
				I2_struct = createI2_struct64(vbtManager, G_struct, H1_struct, C_struct, E_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				H1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				I2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (I1_struct == null) {
				CppCompositeType G1_struct = createG1_struct64(vbtManager, C_struct, E_struct);
				CppCompositeType H_struct = createH_struct64(vbtManager, C_struct);
				I1_struct = createI1_struct64(vbtManager, G1_struct, H_struct, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				H_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				I1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			J2_struct.addDirectBaseClass(I2_struct, 0);
			J2_struct.addDirectBaseClass(I1_struct, 40);
			J2_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			J2_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr64, 2);
			J2_struct.addMember("j21", u4, false, 80);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J2_struct;
	}

	//==============================================================================================
	/*
	 * struct J3 : I2, I1, A {
	 *	  int j31;
	 *	  void j3f();
	 *	};
	 */
	static CppCompositeType createJ3_struct32(VbtManager vbtManager) {
		return createJ3_struct32(vbtManager, null, null, null, null, null);
	}

	static CppCompositeType createJ3_struct32(VbtManager vbtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType A_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		CppCompositeType J3_struct = createStruct32("J3", 60);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (I2_struct == null) {
				CppCompositeType G_struct = createG_struct32(vbtManager, C_struct);
				CppCompositeType H1_struct = createH1_struct32(vbtManager, E_struct, C_struct);
				I2_struct = createI2_struct32(vbtManager, G_struct, H1_struct, C_struct, E_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				H1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				I2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (I1_struct == null) {
				CppCompositeType G1_struct = createG1_struct32(vbtManager, C_struct, E_struct);
				CppCompositeType H_struct = createH_struct32(vbtManager, C_struct);
				I1_struct = createI1_struct32(vbtManager, G1_struct, H_struct, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				H_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				I1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (A_struct == null) {
				A_struct = createA_struct32(vbtManager);
				A_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			J3_struct.addDirectBaseClass(I2_struct, 0);
			J3_struct.addDirectBaseClass(I1_struct, 20);
			J3_struct.addDirectBaseClass(A_struct, 40);
			J3_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			J3_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			J3_struct.addMember("j31", u4, false, 48);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J3_struct;
	}

	//==============================================================================================
	/*
	 * struct J3 : I2, I1, A {
	 *	  int j31;
	 *	  void j3f();
	 *	};
	 */
	static CppCompositeType createJ3_struct64(VbtManager vbtManager) {
		return createJ3_struct64(vbtManager, null, null, null, null, null);
	}

	static CppCompositeType createJ3_struct64(VbtManager vbtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType A_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		CppCompositeType J3_struct = createStruct64("J3", 104);
		try {
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (I2_struct == null) {
				CppCompositeType G_struct = createG_struct64(vbtManager, C_struct);
				CppCompositeType H1_struct = createH1_struct64(vbtManager, E_struct, C_struct);
				I2_struct = createI2_struct64(vbtManager, G_struct, H1_struct, C_struct, E_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				H1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				I2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (I1_struct == null) {
				CppCompositeType G1_struct = createG1_struct64(vbtManager, C_struct, E_struct);
				CppCompositeType H_struct = createH_struct64(vbtManager, C_struct);
				I1_struct = createI1_struct32(vbtManager, G1_struct, H_struct, C_struct, E_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				H_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				I1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (A_struct == null) {
				A_struct = createA_struct64(vbtManager);
				A_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			J3_struct.addDirectBaseClass(I2_struct, 0);
			J3_struct.addDirectBaseClass(I1_struct, 40);
			J3_struct.addDirectBaseClass(A_struct, 80);
			J3_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			J3_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr64, 2);
			J3_struct.addMember("j31", u4, false, 88);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J3_struct;
	}

	//==============================================================================================
	/*
	 * struct J4 : I3, GG1, I, A, virtual GG2, virtual GG3 {
	 *	  int j41;
	 *	  void j4f();
	 *	};
	 */
	static CppCompositeType createJ4_struct32(VbtManager vbtManager) {
		return createJ4_struct32(vbtManager, null, null, null, null, null, null, null, null, null,
			null);
	}

	static CppCompositeType createJ4_struct32(VbtManager vbtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		CppCompositeType J4_struct = createStruct32("J4", 92);
		try {
			if (A_struct == null) {
				A_struct = createA_struct32(vbtManager);
				A_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (CC1_struct == null) {
				CC1_struct = createCC1_struct32(vbtManager);
				CC1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vbtManager);
				CC2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (I3_struct == null) {
				CppCompositeType G1_struct = createG1_struct32(vbtManager, C_struct, E_struct);
				CppCompositeType H1_struct = createH1_struct32(vbtManager, E_struct, C_struct);
				I3_struct = createI3_struct32(vbtManager, G1_struct, H1_struct, E_struct, C_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				H1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				I3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (GG1_struct == null) {
				GG1_struct = createGG1_struct32(vbtManager, CC1_struct);
				GG1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (I_struct == null) {
				CppCompositeType G_struct = createG_struct32(vbtManager, C_struct);
				CppCompositeType H_struct = createH_struct32(vbtManager, C_struct);
				I_struct = createI_struct32(vbtManager, G_struct, H_struct, C_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				H_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				I_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (GG2_struct == null) {
				GG2_struct = createGG2_struct32(vbtManager, CC2_struct);
				GG2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (GG3_struct == null) {
				GG3_struct = createGG3_struct32(vbtManager, CC2_struct);
				GG3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			J4_struct.addDirectBaseClass(I3_struct, 0);
			J4_struct.addDirectBaseClass(GG1_struct, 20);
			J4_struct.addDirectBaseClass(I_struct, 28);
			J4_struct.addDirectBaseClass(A_struct, 48);
			J4_struct.addDirectVirtualBaseClass(GG2_struct, 0, vbptr32, 5);
			J4_struct.addDirectVirtualBaseClass(GG3_struct, 0, vbptr32, 6);
			J4_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			J4_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			J4_struct.addIndirectVirtualBaseClass(CC1_struct, 0, vbptr32, 3);
			J4_struct.addIndirectVirtualBaseClass(CC2_struct, 0, vbptr32, 4);
			J4_struct.addMember("j41", u4, false, 56);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J4_struct;
	}

	//==============================================================================================
	/*
	 * struct J4 : I3, GG1, I, A, virtual GG2, virtual GG3 {
	 *	  int j41;
	 *	  void j4f();
	 *	};
	 */
	static CppCompositeType createJ4_struct64(VbtManager vbtManager) {
		return createJ4_struct64(vbtManager, null, null, null, null, null, null, null, null, null,
			null);
	}

	static CppCompositeType createJ4_struct64(VbtManager vbtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		CppCompositeType J4_struct = createStruct64("J4", 160);
		try {
			if (A_struct == null) {
				A_struct = createA_struct64(vbtManager);
				A_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (CC1_struct == null) {
				CC1_struct = createCC1_struct64(vbtManager);
				CC1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct64(vbtManager);
				CC2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (I3_struct == null) {
				CppCompositeType G1_struct = createG1_struct64(vbtManager, C_struct, E_struct);
				CppCompositeType H1_struct = createH1_struct64(vbtManager, E_struct, C_struct);
				I3_struct = createI3_struct32(vbtManager, G1_struct, H1_struct, E_struct, C_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				H1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				I3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (GG1_struct == null) {
				GG1_struct = createGG1_struct64(vbtManager, CC1_struct);
				GG1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (I_struct == null) {
				CppCompositeType G_struct = createG_struct64(vbtManager, C_struct);
				CppCompositeType H_struct = createH_struct64(vbtManager, C_struct);
				I_struct = createI_struct32(vbtManager, G_struct, H_struct, C_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				H_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				I_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (GG2_struct == null) {
				GG2_struct = createGG2_struct64(vbtManager, CC2_struct);
				GG2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (GG3_struct == null) {
				GG3_struct = createGG3_struct64(vbtManager, CC2_struct);
				GG3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			J4_struct.addDirectBaseClass(I3_struct, 0);
			J4_struct.addDirectBaseClass(GG1_struct, 40);
			J4_struct.addDirectBaseClass(I_struct, 56);
			J4_struct.addDirectBaseClass(A_struct, 96);
			J4_struct.addDirectVirtualBaseClass(GG2_struct, 0, vbptr64, 5);
			J4_struct.addDirectVirtualBaseClass(GG3_struct, 0, vbptr64, 6);
			J4_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr64, 1);
			J4_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr64, 2);
			J4_struct.addIndirectVirtualBaseClass(CC1_struct, 0, vbptr64, 3);
			J4_struct.addIndirectVirtualBaseClass(CC2_struct, 0, vbptr64, 4);
			J4_struct.addMember("j41", u4, false, 104);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J4_struct;
	}

	//==============================================================================================
	/*
	 * struct J4 : virtual GG2, virtual GG3, I3, GG1, I, A  {
	 *	  int j51;
	 *	  void j5f();
	 *	};
	 */
	static CppCompositeType createJ5_syntactic_struct32(VbtManager vbtManager) {
		return createJ5_syntactic_struct32(vbtManager, null, null, null, null, null, null, null,
			null, null, null);
	}

	static CppCompositeType createJ5_syntactic_struct32(VbtManager vbtManager,
			CppCompositeType I3_struct, CppCompositeType GG1_struct, CppCompositeType I_struct,
			CppCompositeType A_struct, CppCompositeType GG2_struct, CppCompositeType GG3_struct,
			CppCompositeType C_struct, CppCompositeType E_struct, CppCompositeType CC1_struct,
			CppCompositeType CC2_struct) {
		CppCompositeType J5_struct = createStruct32("J5", 0); // TODO need without size
		try {
			if (A_struct == null) {
				A_struct = createA_syntactic_struct32(vbtManager);
			}
			if (C_struct == null) {
				C_struct = createC_syntactic_struct32(vbtManager);
			}
			if (E_struct == null) {
				E_struct = createE_syntactic_struct32(vbtManager);
			}
			if (CC1_struct == null) {
				CC1_struct = createCC1_syntactic_struct32(vbtManager);
			}
			if (CC2_struct == null) {
				CC2_struct = createCC2_syntactic_struct32(vbtManager);
			}
			if (I3_struct == null) {
				CppCompositeType G1_struct =
					createG1_syntactic_struct32(vbtManager, C_struct, E_struct);
				CppCompositeType H1_struct =
					createH1_syntactic_struct32(vbtManager, E_struct, C_struct);
				I3_struct = createI3_syntactic_struct32(vbtManager, G1_struct, H1_struct, E_struct,
					C_struct);
			}
			if (GG1_struct == null) {
				GG1_struct = createGG1_syntactic_struct32(vbtManager, CC1_struct);
			}
			if (I_struct == null) {
				CppCompositeType G_struct = createG_syntactic_struct32(vbtManager, C_struct);
				CppCompositeType H_struct = createH_syntactic_struct32(vbtManager, C_struct);
				I_struct = createI_syntactic_struct32(vbtManager, G_struct, H_struct, C_struct);
			}
			if (GG2_struct == null) {
				GG2_struct = createGG2_syntactic_struct32(vbtManager, CC2_struct);
			}
			if (GG3_struct == null) {
				GG3_struct = createGG3_syntactic_struct32(vbtManager, CC2_struct);
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
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J5_struct;
	}

	//==============================================================================================
	/*
	 * struct J4 : virtual GG2, virtual GG3, I3, GG1, I, A  {
	 *	  int j51;
	 *	  void j5f();
	 *	};
	 */
	static CppCompositeType createJ5_struct32(VbtManager vbtManager) {
		return createJ5_struct32(vbtManager, null, null, null, null, null, null, null, null, null,
			null);
	}

	static CppCompositeType createJ5_struct32(VbtManager vbtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		CppCompositeType J5_struct = createStruct32("J5", 92);
		try {
			if (A_struct == null) {
				A_struct = createA_struct32(vbtManager);
				A_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (CC1_struct == null) {
				CC1_struct = createCC1_struct32(vbtManager);
				CC1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vbtManager);
				CC2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (I3_struct == null) {
				CppCompositeType G1_struct = createG1_struct32(vbtManager, C_struct, E_struct);
				CppCompositeType H1_struct = createH1_struct32(vbtManager, E_struct, C_struct);
				I3_struct = createI3_struct32(vbtManager, G1_struct, H1_struct, E_struct, C_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				H1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				I3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (GG1_struct == null) {
				GG1_struct = createGG1_struct32(vbtManager, CC1_struct);
				GG1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (I_struct == null) {
				CppCompositeType G_struct = createG_struct32(vbtManager, C_struct);
				CppCompositeType H_struct = createH_struct32(vbtManager, C_struct);
				I_struct = createI_struct32(vbtManager, G_struct, H_struct, C_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				H_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
				I_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (GG2_struct == null) {
				GG2_struct = createGG2_struct32(vbtManager, CC2_struct);
				GG2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (GG3_struct == null) {
				GG3_struct = createGG3_struct32(vbtManager, CC2_struct);
				GG3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			J5_struct.addDirectBaseClass(I3_struct, 0);
			J5_struct.addDirectBaseClass(GG1_struct, 20);
			J5_struct.addDirectBaseClass(I_struct, 28);
			J5_struct.addDirectBaseClass(A_struct, 48);
			J5_struct.addDirectVirtualBaseClass(GG2_struct, 0, vbptr32, 4);
			J5_struct.addDirectVirtualBaseClass(GG3_struct, 0, vbptr32, 5);
			J5_struct.addIndirectVirtualBaseClass(CC2_struct, 0, vbptr32, 3);
			J5_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			J5_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			J5_struct.addIndirectVirtualBaseClass(CC1_struct, 0, vbptr32, 6);
			J5_struct.addMember("j51", u4, false, 56);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J5_struct;
	}

	//==============================================================================================
	/*
	 * struct J4 : virtual GG2, virtual GG3, I3, GG1, I, A  {
	 *	  int j51;
	 *	  void j5f();
	 *	};
	 */
	static CppCompositeType createJ5_struct64(VbtManager vbtManager) {
		return createJ5_struct64(vbtManager, null, null, null, null, null, null, null, null, null,
			null);
	}

	static CppCompositeType createJ5_struct64(VbtManager vbtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		CppCompositeType J5_struct = createStruct64("J5", 164);
		try {
			if (A_struct == null) {
				A_struct = createA_struct64(vbtManager);
				A_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (C_struct == null) {
				C_struct = createC_struct64(vbtManager);
				C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (E_struct == null) {
				E_struct = createE_struct64(vbtManager);
				E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (CC1_struct == null) {
				CC1_struct = createCC1_struct64(vbtManager);
				CC1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct64(vbtManager);
				CC2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (I3_struct == null) {
				CppCompositeType G1_struct = createG1_struct64(vbtManager, C_struct, E_struct);
				CppCompositeType H1_struct = createH1_struct64(vbtManager, E_struct, C_struct);
				I3_struct = createI3_struct32(vbtManager, G1_struct, H1_struct, E_struct, C_struct);
				G1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				H1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				I3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (GG1_struct == null) {
				GG1_struct = createGG1_struct32(vbtManager, CC1_struct);
				GG1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (I_struct == null) {
				CppCompositeType G_struct = createG_struct64(vbtManager, C_struct);
				CppCompositeType H_struct = createH_struct64(vbtManager, C_struct);
				I_struct = createI_struct32(vbtManager, G_struct, H_struct, C_struct);
				G_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				H_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
				I_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (GG2_struct == null) {
				GG2_struct = createGG2_struct64(vbtManager, CC2_struct);
				GG2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (GG3_struct == null) {
				GG3_struct = createGG3_struct64(vbtManager, CC2_struct);
				GG3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			J5_struct.addDirectBaseClass(I3_struct, 0);
			J5_struct.addDirectBaseClass(GG1_struct, 40);
			J5_struct.addDirectBaseClass(I_struct, 56);
			J5_struct.addDirectBaseClass(A_struct, 96);
			J5_struct.addDirectVirtualBaseClass(GG2_struct, 0, vbptr32, 4);
			J5_struct.addDirectVirtualBaseClass(GG3_struct, 0, vbptr32, 5);
			J5_struct.addIndirectVirtualBaseClass(CC2_struct, 0, vbptr32, 3);
			J5_struct.addIndirectVirtualBaseClass(C_struct, 0, vbptr32, 1);
			J5_struct.addIndirectVirtualBaseClass(E_struct, 0, vbptr32, 2);
			J5_struct.addIndirectVirtualBaseClass(CC1_struct, 0, vbptr32, 6);
			J5_struct.addMember("j51", u4, false, 104);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J5_struct;
	}

	//==============================================================================================
	/*
	 * struct J6 : virtual GG4, virtual GG3, A { //GG4 has no members
	 *    int j61;
	 *	  void j6f();
	 * };
	 */
	static CppCompositeType createJ6_struct32(VbtManager vbtManager) {
		return createJ6_struct32(vbtManager, null, null, null, null, null);
	}

	static CppCompositeType createJ6_struct32(VbtManager vbtManager, CppCompositeType A_struct,
			CppCompositeType GG4_struct, CppCompositeType GG3_struct, CppCompositeType CC2_struct,
			CppCompositeType CC3_struct) {
		CppCompositeType J6_struct = createStruct32("J6", 36);
		try {
			if (A_struct == null) {
				A_struct = createA_struct32(vbtManager);
				A_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vbtManager);
				CC2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (CC3_struct == null) {
				CC3_struct = createCC3_struct32(vbtManager);
				CC3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (GG4_struct == null) {
				GG4_struct = createGG4_struct32(vbtManager, CC3_struct);
				GG4_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			if (GG3_struct == null) {
				GG3_struct = createGG3_struct32(vbtManager, CC2_struct);
				GG3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
			}
			J6_struct.addDirectBaseClass(A_struct, 0);
			J6_struct.addDirectVirtualBaseClass(GG4_struct, 8, vbptr32, 2);
			J6_struct.addDirectVirtualBaseClass(GG3_struct, 8, vbptr32, 4);
			J6_struct.addIndirectVirtualBaseClass(CC3_struct, 8, vbptr32, 1);
			J6_struct.addIndirectVirtualBaseClass(CC2_struct, 8, vbptr32, 3);
			J6_struct.addMember("j61", u4, false, 12);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J6_struct;
	}

	//==============================================================================================
	/*
	 * struct J6 : virtual GG4, virtual GG3, A { //GG4 has no members
	 *    int j61;
	 *	  void j6f();
	 * };
	 */
	static CppCompositeType createJ6_struct64(VbtManager vbtManager) {
		return createJ6_struct64(vbtManager, null, null, null, null, null);
	}

	static CppCompositeType createJ6_struct64(VbtManager vbtManager, CppCompositeType A_struct,
			CppCompositeType GG4_struct, CppCompositeType GG3_struct, CppCompositeType CC2_struct,
			CppCompositeType CC3_struct) {
		CppCompositeType J6_struct = createStruct64("J6", 64);
		try {
			if (A_struct == null) {
				A_struct = createA_struct64(vbtManager);
				A_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct64(vbtManager);
				CC2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (CC3_struct == null) {
				CC3_struct = createCC3_struct64(vbtManager);
				CC3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (GG4_struct == null) {
				GG4_struct = createGG4_struct64(vbtManager, CC3_struct);
				GG4_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			if (GG3_struct == null) {
				GG3_struct = createGG3_struct64(vbtManager, CC2_struct);
				GG3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
			}
			J6_struct.addDirectBaseClass(A_struct, 0);
			J6_struct.addDirectVirtualBaseClass(GG4_struct, 8, vbptr64, 2);
			J6_struct.addDirectVirtualBaseClass(GG3_struct, 8, vbptr64, 4);
			J6_struct.addIndirectVirtualBaseClass(CC3_struct, 8, vbptr64, 1);
			J6_struct.addIndirectVirtualBaseClass(CC2_struct, 8, vbptr64, 3);
			J6_struct.addMember("j61", u4, false, 16);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J6_struct;
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
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
	@Test
	public void testA_32_vbt() throws Exception {
		CppCompositeType A_struct = createA_struct32(pdbVbtManager32);
		A_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = A_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedA_32(), composite, true);
	}

	@Test
	public void testA_32_speculative() throws Exception {
		CppCompositeType A_struct = createA_struct32(vbtManager32);
		A_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = A_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedA_32(), composite, true);
	}

	private String getExpectedA_32() {
		String expected =
		//@formatter:off
			"/A\n" + 
			"pack()\n" + 
			"Structure A {\n" + 
			"   0   A_direct   8      \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/A/A_direct\n" + 
			"pack()\n" + 
			"Structure A_direct {\n" + 
			"   0   undefined1   1   c   \"\"\n" + 
			"   4   undefined4   4   i   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedA_32() {
		return convertCommentsToSpeculative(getExpectedA_32());
	}

	//==============================================================================================
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
	@Test
	public void testA_64_vbt() throws Exception {
		CppCompositeType A_struct = createA_struct64(pdbVbtManager64);
		A_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = A_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedA_64(), composite, true);
	}

	@Test
	public void testA_64_speculative() throws Exception {
		CppCompositeType A_struct = createA_struct64(vbtManager64);
		A_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = A_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedA_64(), composite, true);
	}

	private String getExpectedA_64() {
		String expected =
		//@formatter:off
			"/A\n" + 
			"pack()\n" + 
			"Structure A {\n" + 
			"   0   A_direct   8      \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/A/A_direct\n" + 
			"pack()\n" + 
			"Structure A_direct {\n" + 
			"   0   undefined1   1   c   \"\"\n" + 
			"   4   undefined4   4   i   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedA_64() {
		return convertCommentsToSpeculative(getExpectedA_64());
	}

	//==============================================================================================
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
	@Test
	public void testC_32_vbt() throws Exception {
		CppCompositeType C_struct = createC_struct32(pdbVbtManager32);
		C_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = C_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedC_32(), composite, true);
	}

	@Test
	public void testC_32_speculative() throws Exception {
		CppCompositeType C_struct = createC_struct32(vbtManager32);
		C_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = C_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedC_32(), composite, true);
	}

	private String getExpectedC_32() {
		String expected =
		//@formatter:off
			"/C\n" + 
			"pack()\n" + 
			"Structure C {\n" + 
			"   0   C_direct   4      \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedC_32() {
		return convertCommentsToSpeculative(getExpectedC_32());
	}

	//==============================================================================================
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
	@Test
	public void testC_64_vbt() throws Exception {
		CppCompositeType C_struct = createC_struct64(pdbVbtManager64);
		C_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = C_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedC_64(), composite, true);
	}

	@Test
	public void testC_64_speculative() throws Exception {
		CppCompositeType C_struct = createC_struct64(vbtManager64);
		C_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = C_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedC_64(), composite, true);
	}

	private String getExpectedC_64() {
		String expected =
		//@formatter:off
			"/C\n" + 
			"pack()\n" + 
			"Structure C {\n" + 
			"   0   C_direct   4      \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedC_64() {
		return convertCommentsToSpeculative(getExpectedC_64());
	}

	//==============================================================================================
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
	@Test
	public void testCC1_32_vbt() throws Exception {
		CppCompositeType CC1_struct = createCC1_struct32(pdbVbtManager32);
		CC1_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = CC1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedCC1_32(), composite, true);
	}

	@Test
	public void testCC1_32_speculative() throws Exception {
		CppCompositeType CC1_struct = createCC1_struct32(vbtManager32);
		CC1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = CC1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedCC1_32(), composite, true);
	}

	private String getExpectedCC1_32() {
		String expected =
		//@formatter:off
			"/CC1\n" + 
			"pack()\n" + 
			"Structure CC1 {\n" + 
			"   0   CC1_direct   4      \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC1/CC1_direct\n" + 
			"pack()\n" + 
			"Structure CC1_direct {\n" + 
			"   0   undefined4   4   cc11   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC1_32() {
		return convertCommentsToSpeculative(getExpectedCC1_32());
	}

	//==============================================================================================
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
	@Test
	public void testCC1_64_vbt() throws Exception {
		CppCompositeType CC1_struct = createCC1_struct64(pdbVbtManager64);
		CC1_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = CC1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedCC1_64(), composite, true);
	}

	@Test
	public void testCC1_64_speculative() throws Exception {
		CppCompositeType CC1_struct = createCC1_struct64(vbtManager64);
		CC1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = CC1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedCC1_64(), composite, true);
	}

	private String getExpectedCC1_64() {
		String expected =
		//@formatter:off
			"/CC1\n" + 
			"pack()\n" + 
			"Structure CC1 {\n" + 
			"   0   CC1_direct   4      \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC1/CC1_direct\n" + 
			"pack()\n" + 
			"Structure CC1_direct {\n" + 
			"   0   undefined4   4   cc11   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC1_64() {
		return convertCommentsToSpeculative(getExpectedCC1_64());
	}

	//==============================================================================================
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
	@Test
	public void testCC2_32_vbt() throws Exception {
		CppCompositeType CC2_struct = createCC2_struct32(pdbVbtManager32);
		CC2_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = CC2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedCC2_32(), composite, true);
	}

	@Test
	public void testCC2_32_speculative() throws Exception {
		CppCompositeType CC2_struct = createCC2_struct32(vbtManager32);
		CC2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = CC2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedCC2_32(), composite, true);
	}

	private String getExpectedCC2_32() {
		String expected =
		//@formatter:off
			"/CC2\n" + 
			"pack()\n" + 
			"Structure CC2 {\n" + 
			"   0   CC2_direct   4      \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC2_32() {
		return convertCommentsToSpeculative(getExpectedCC2_32());
	}

	//==============================================================================================
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
	@Test
	public void testCC2_64_vbt() throws Exception {
		CppCompositeType CC2_struct = createCC2_struct64(pdbVbtManager64);
		CC2_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = CC2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedCC2_64(), composite, true);
	}

	@Test
	public void testCC2_64_speculative() throws Exception {
		CppCompositeType CC2_struct = createCC2_struct64(vbtManager64);
		CC2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = CC2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedCC2_64(), composite, true);
	}

	private String getExpectedCC2_64() {
		String expected =
		//@formatter:off
			"/CC2\n" + 
			"pack()\n" + 
			"Structure CC2 {\n" + 
			"   0   CC2_direct   4      \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC2_64() {
		return convertCommentsToSpeculative(getExpectedCC2_64());
	}

	//==============================================================================================
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
	@Test
	public void testCC3_32_vbt() throws Exception {
		CppCompositeType CC3_struct = createCC3_struct32(pdbVbtManager32);
		CC3_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = CC3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedCC3_32(), composite, true);
	}

	@Test
	public void testCC3_32_speculative() throws Exception {
		CppCompositeType CC3_struct = createCC3_struct32(vbtManager32);
		CC3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = CC3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedCC3_32(), composite, true);
	}

	private String getExpectedCC3_32() {
		String expected =
		//@formatter:off
			"/CC3\n" + 
			"pack(disabled)\n" + 
			"Structure CC3 {\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC3_32() {
		return convertCommentsToSpeculative(getExpectedCC3_32());
	}

	//==============================================================================================
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
	@Test
	public void testCC3_64_vbt() throws Exception {
		CppCompositeType CC3_struct = createCC3_struct64(pdbVbtManager64);
		CC3_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = CC3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedCC3_64(), composite, true);
	}

	@Test
	public void testCC3_64_speculative() throws Exception {
		CppCompositeType CC3_struct = createCC3_struct64(vbtManager64);
		CC3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = CC3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedCC3_64(), composite, true);
	}

	private String getExpectedCC3_64() {
		String expected =
		//@formatter:off
			"/CC3\n" + 
			"pack(disabled)\n" + 
			"Structure CC3 {\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedCC3_64() {
		return convertCommentsToSpeculative(getExpectedCC3_64());
	}

	//==============================================================================================
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
	@Test
	public void testD_32_vbt() throws Exception {
		CppCompositeType D_struct = createD_struct32(pdbVbtManager32);
		D_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = D_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedD_32(), composite, true);
	}

	@Test
	public void testD_32_speculative() throws Exception {
		CppCompositeType D_struct = createD_struct32(vbtManager32);
		D_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = D_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedD_32(), composite, true);
	}

	private String getExpectedD_32() {
		String expected =
		//@formatter:off
			"/D\n" + 
			"pack()\n" + 
			"Structure D {\n" + 
			"   0   D_direct   8      \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/D/D_direct\n" + 
			"pack()\n" + 
			"Structure D_direct {\n" + 
			"   0   C_direct   4      \"\"\n" + 
			"   4   undefined4   4   d1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedD_32() {
		return convertCommentsToSpeculative(getExpectedD_32());
	}

	//==============================================================================================
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
	@Test
	public void testD_64_vbt() throws Exception {
		CppCompositeType D_struct = createD_struct64(pdbVbtManager64);
		D_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = D_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedD_64(), composite, true);
	}

	@Test
	public void testD_64_speculative() throws Exception {
		CppCompositeType D_struct = createD_struct64(vbtManager64);
		D_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = D_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedD_64(), composite, true);
	}

	private String getExpectedD_64() {
		String expected =
		//@formatter:off
			"/D\n" + 
			"pack()\n" + 
			"Structure D {\n" + 
			"   0   D_direct   8      \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/D/D_direct\n" + 
			"pack()\n" + 
			"Structure D_direct {\n" + 
			"   0   C_direct   4      \"\"\n" + 
			"   4   undefined4   4   d1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedD_64() {
		return convertCommentsToSpeculative(getExpectedD_64());
	}

	//==============================================================================================
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
	@Test
	public void testE_32_vbt() throws Exception {
		CppCompositeType E_struct = createE_struct32(pdbVbtManager32);
		E_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = E_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedE_32(), composite, true);
	}

	@Test
	public void testE_32_speculative() throws Exception {
		CppCompositeType E_struct = createE_struct32(vbtManager32);
		E_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = E_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedE_32(), composite, true);
	}

	private String getExpectedE_32() {
		String expected =
		//@formatter:off
			"/E\n" + 
			"pack()\n" + 
			"Structure E {\n" + 
			"   0   E_direct   4      \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedE_32() {
		return convertCommentsToSpeculative(getExpectedE_32());
	}

	//==============================================================================================
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
	@Test
	public void testE_64_vbt() throws Exception {
		CppCompositeType E_struct = createE_struct64(pdbVbtManager64);
		E_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = E_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedE_64(), composite, true);
	}

	@Test
	public void testE_64_speculative() throws Exception {
		CppCompositeType E_struct = createE_struct64(vbtManager64);
		E_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = E_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedE_64(), composite, true);
	}

	private String getExpectedE_64() {
		String expected =
		//@formatter:off
			"/E\n" + 
			"pack()\n" + 
			"Structure E {\n" + 
			"   0   E_direct   4      \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedE_64() {
		return convertCommentsToSpeculative(getExpectedE_64());
	}

	//==============================================================================================
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
	@Test
	public void testF_32_vbt() throws Exception {
		CppCompositeType F_struct = createF_struct32(pdbVbtManager32);
		F_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = F_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedF_32(), composite, true);
	}

	@Test
	public void testF_32_speculative() throws Exception {
		CppCompositeType F_struct = createF_struct32(vbtManager32);
		F_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = F_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedF_32(), composite, true);
	}

	private String getExpectedF_32() {
		String expected =
		//@formatter:off
			"/F\n" + 
			"pack()\n" + 
			"Structure F {\n" + 
			"   0   F_direct   12      \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/F/F_direct\n" + 
			"pack()\n" + 
			"Structure F_direct {\n" + 
			"   0   C_direct   4      \"\"\n" + 
			"   4   E_direct   4      \"\"\n" + 
			"   8   undefined4   4   f1   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedF_32() {
		return convertCommentsToSpeculative(getExpectedF_32());
	}

	//==============================================================================================
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
	@Test
	public void testF_64_vbt() throws Exception {
		CppCompositeType F_struct = createF_struct64(pdbVbtManager64);
		F_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = F_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedF_64(), composite, true);
	}

	@Test
	public void testF_64_speculative() throws Exception {
		CppCompositeType F_struct = createF_struct64(vbtManager64);
		F_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = F_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedF_64(), composite, true);
	}

	private String getExpectedF_64() {
		String expected =
		//@formatter:off
			"/F\n" + 
			"pack()\n" + 
			"Structure F {\n" + 
			"   0   F_direct   12      \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/F/F_direct\n" + 
			"pack()\n" + 
			"Structure F_direct {\n" + 
			"   0   C_direct   4      \"\"\n" + 
			"   4   E_direct   4      \"\"\n" + 
			"   8   undefined4   4   f1   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedF_64() {
		return convertCommentsToSpeculative(getExpectedF_64());
	}

	//==============================================================================================
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
	@Test
	public void testG_32_vbt() throws Exception {
		CppCompositeType G_struct = createG_struct32(pdbVbtManager32);
		G_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = G_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedG_32(), composite, true);
	}

	@Test
	public void testG_32_speculative() throws Exception {
		CppCompositeType G_struct = createG_struct32(vbtManager32);
		G_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = G_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedG_32(), composite, true);
	}

	private String getExpectedG_32() {
		String expected =
		//@formatter:off
			"/G\n" + 
			"pack()\n" + 
			"Structure G {\n" + 
			"   0   G_direct   8      \"\"\n" + 
			"   8   C_direct   4      \"(Virtual Base C)\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedG_32() {
		return convertCommentsToSpeculative(getExpectedG_32());
	}

	//==============================================================================================
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
	@Test
	public void testG_64_vbt() throws Exception {
		CppCompositeType G_struct = createG_struct64(pdbVbtManager64);
		G_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = G_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedG_64(), composite, true);
	}

	@Test
	public void testG_64_speculative() throws Exception {
		CppCompositeType G_struct = createG_struct64(vbtManager64);
		G_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = G_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedG_64(), composite, true);
	}

	private String getExpectedG_64() {
		String expected =
		//@formatter:off
			"/G\n" + 
			"pack()\n" + 
				"Structure G {\n" + 
			"   0   G_direct   16      \"\"\n" + 
			"   16   C_direct   4      \"(Virtual Base C)\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedG_64() {
		return convertCommentsToSpeculative(getExpectedG_64());
	}

	//==============================================================================================
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
	@Test
	public void testH_32_vbt() throws Exception {
		CppCompositeType H_struct = createH_struct32(pdbVbtManager32);
		H_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = H_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedH_32(), composite, true);
	}

	@Test
	public void testH_32_speculative() throws Exception {
		CppCompositeType H_struct = createH_struct32(vbtManager32);
		H_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = H_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedH_32(), composite, true);
	}

	private String getExpectedH_32() {
		String expected =
		//@formatter:off
			"/H\n" + 
			"pack()\n" + 
			"Structure H {\n" + 
			"   0   H_direct   8      \"\"\n" + 
			"   8   C_direct   4      \"(Virtual Base C)\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedH_32() {
		return convertCommentsToSpeculative(getExpectedH_32());
	}

	//==============================================================================================
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
	@Test
	public void testH_64_vbt() throws Exception {
		CppCompositeType H_struct = createH_struct64(pdbVbtManager64);
		H_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = H_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedH_64(), composite, true);
	}

	@Test
	public void testH_64_speculative() throws Exception {
		CppCompositeType H_struct = createH_struct64(vbtManager64);
		H_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = H_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedH_64(), composite, true);
	}

	private String getExpectedH_64() {
		String expected =
		//@formatter:off
			"/H\n" + 
			"pack()\n" + 
			"Structure H {\n" + 
			"   0   H_direct   16      \"\"\n" + 
			"   16   C_direct   4      \"(Virtual Base C)\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedH_64() {
		return convertCommentsToSpeculative(getExpectedH_64());
	}

	//==============================================================================================
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
	@Test
	public void testG1_32_vbt() throws Exception {
		CppCompositeType G1_struct = createG1_struct32(pdbVbtManager32);
		G1_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = G1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedG1_32(), composite, true);
	}

	@Test
	public void testG1_32_speculative() throws Exception {
		CppCompositeType G1_struct = createG1_struct32(vbtManager32);
		G1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = G1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedG1_32(), composite, true);
	}

	private String getExpectedG1_32() {
		String expected =
		//@formatter:off
			"/G1\n" + 
			"pack()\n" + 
			"Structure G1 {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   12   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedG1_32() {
		return convertCommentsToSpeculative(getExpectedG1_32());
	}

	//==============================================================================================
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
	@Test
	public void testG1_64_vbt() throws Exception {
		CppCompositeType G1_struct = createG1_struct64(pdbVbtManager64);
		G1_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = G1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedG1_64(), composite, true);
	}

	@Test
	public void testG1_64_speculative() throws Exception {
		CppCompositeType G1_struct = createG1_struct64(vbtManager64);
		G1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = G1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedG1_64(), composite, true);
	}

	private String getExpectedG1_64() {
		String expected =
		//@formatter:off
			"/G1\n" + 
			"pack()\n" + 
			"Structure G1 {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   20   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedG1_64() {
		return convertCommentsToSpeculative(getExpectedG1_64());
	}

	//==============================================================================================
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
	@Test
	public void testH1_32_vbt() throws Exception {
		CppCompositeType H1_struct = createH1_struct32(pdbVbtManager32);
		H1_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = H1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedH1_32(), composite, true);
	}

	@Test
	public void testH1_32_speculative() throws Exception {
		CppCompositeType H1_struct = createH1_struct32(vbtManager32);
		H1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = H1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedH1_32(), composite, true);
	}

	private String getExpectedH1_32() {
		String expected =
		//@formatter:off
			"/H1\n" + 
			"pack()\n" + 
			"Structure H1 {\n" + 
			"   0   H1_direct   8      \"\"\n" + 
			"   8   E_direct   4      \"(Virtual Base E)\"\n" + 
			"   12   C_direct   4      \"(Virtual Base C)\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedH1_32() {
		return convertCommentsToSpeculative(getExpectedH1_32());
	}

	//==============================================================================================
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
	@Test
	public void testH1_64_vbt() throws Exception {
		CppCompositeType H1_struct = createH1_struct64(pdbVbtManager64);
		H1_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = H1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedH1_64(), composite, true);
	}

	@Test
	public void testH1_64_speculative() throws Exception {
		CppCompositeType H1_struct = createH1_struct64(vbtManager64);
		H1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = H1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedH1_64(), composite, true);
	}

	private String getExpectedH1_64() {
		String expected =
		//@formatter:off
			"/H1\n" + 
			"pack()\n" + 
			"Structure H1 {\n" + 
			"   0   H1_direct   16      \"\"\n" + 
			"   16   E_direct   4      \"(Virtual Base E)\"\n" + 
			"   20   C_direct   4      \"(Virtual Base C)\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedH1_64() {
		return convertCommentsToSpeculative(getExpectedH1_64());
	}

	//==============================================================================================
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
	@Test
	public void testGG1_32_vbt() throws Exception {
		CppCompositeType GG1_struct = createGG1_struct32(pdbVbtManager32);
		GG1_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = GG1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedGG1_32(), composite, true);
	}

	@Test
	public void testGG1_32_speculative() throws Exception {
		CppCompositeType GG1_struct = createGG1_struct32(vbtManager32);
		GG1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = GG1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedGG1_32(), composite, true);
	}

	private String getExpectedGG1_32() {
		String expected =
		//@formatter:off
			"/GG1\n" + 
			"pack()\n" + 
			"Structure GG1 {\n" + 
			"   0   GG1_direct   8      \"\"\n" + 
			"   8   CC1_direct   4      \"(Virtual Base CC1)\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/CC1/CC1_direct\n" + 
			"pack()\n" + 
			"Structure CC1_direct {\n" + 
			"   0   undefined4   4   cc11   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/GG1/GG1_direct\n" + 
			"pack()\n" + 
			"Structure GG1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG1_32() {
		return convertCommentsToSpeculative(getExpectedGG1_32());
	}

	//==============================================================================================
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
	@Test
	public void testGG1_64_vbt() throws Exception {
		CppCompositeType GG1_struct = createGG1_struct64(pdbVbtManager64);
		GG1_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = GG1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedGG1_64(), composite, true);
	}

	@Test
	public void testGG1_64_speculative() throws Exception {
		CppCompositeType GG1_struct = createGG1_struct64(vbtManager64);
		GG1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = GG1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedGG1_64(), composite, true);
	}

	private String getExpectedGG1_64() {
		String expected =
		//@formatter:off
			"/GG1\n" + 
			"pack()\n" + 
			"Structure GG1 {\n" + 
			"   0   GG1_direct   16      \"\"\n" + 
			"   16   CC1_direct   4      \"(Virtual Base CC1)\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8\n" + 
			"/CC1/CC1_direct\n" + 
			"pack()\n" + 
			"Structure CC1_direct {\n" + 
			"   0   undefined4   4   cc11   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/GG1/GG1_direct\n" + 
			"pack()\n" + 
			"Structure GG1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG1_64() {
		return convertCommentsToSpeculative(getExpectedGG1_64());
	}

	//==============================================================================================
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
	@Test
	public void testGG2_32_vbt() throws Exception {
		CppCompositeType GG2_struct = createGG2_struct32(pdbVbtManager32);
		GG2_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = GG2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedGG2_32(), composite, true);
	}

	@Test
	public void testGG2_32_speculative() throws Exception {
		CppCompositeType GG2_struct = createGG2_struct32(vbtManager32);
		GG2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = GG2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedGG2_32(), composite, true);
	}

	private String getExpectedGG2_32() {
		String expected =
		//@formatter:off
			"/GG2\n" + 
			"pack()\n" + 
			"Structure GG2 {\n" + 
			"   0   GG2_direct   8      \"\"\n" + 
			"   8   CC2_direct   4      \"(Virtual Base CC2)\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/GG2/GG2_direct\n" + 
			"pack()\n" + 
			"Structure GG2_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg21   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG2_32() {
		return convertCommentsToSpeculative(getExpectedGG2_32());
	}

	//==============================================================================================
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
	@Test
	public void testGG2_64_vbt() throws Exception {
		CppCompositeType GG2_struct = createGG2_struct64(pdbVbtManager64);
		GG2_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = GG2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedGG2_64(), composite, true);
	}

	@Test
	public void testGG2_64_speculative() throws Exception {
		CppCompositeType GG2_struct = createGG2_struct64(vbtManager64);
		GG2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = GG2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedGG2_64(), composite, true);
	}

	private String getExpectedGG2_64() {
		String expected =
		//@formatter:off
			"/GG2\n" + 
			"pack()\n" + 
			"Structure GG2 {\n" + 
			"   0   GG2_direct   16      \"\"\n" + 
			"   16   CC2_direct   4      \"(Virtual Base CC2)\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/GG2/GG2_direct\n" + 
			"pack()\n" + 
			"Structure GG2_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg21   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG2_64() {
		return convertCommentsToSpeculative(getExpectedGG2_64());
	}

	//==============================================================================================
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
	@Test
	public void testGG3_32_vbt() throws Exception {
		CppCompositeType GG3_struct = createGG3_struct32(pdbVbtManager32);
		GG3_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = GG3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedGG3_32(), composite, true);
	}

	@Test
	public void testGG3_32_speculative() throws Exception {
		CppCompositeType GG3_struct = createGG3_struct32(vbtManager32);
		GG3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = GG3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedGG3_32(), composite, true);
	}

	private String getExpectedGG3_32() {
		String expected =
		//@formatter:off
			"/GG3\n" + 
			"pack()\n" + 
			"Structure GG3 {\n" + 
			"   0   GG3_direct   8      \"\"\n" + 
			"   8   CC2_direct   4      \"(Virtual Base CC2)\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/GG3/GG3_direct\n" + 
			"pack()\n" + 
			"Structure GG3_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg31   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG3_32() {
		return convertCommentsToSpeculative(getExpectedGG3_32());
	}

	//==============================================================================================
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
	@Test
	public void testGG3_64_vbt() throws Exception {
		CppCompositeType GG3_struct = createGG3_struct64(pdbVbtManager64);
		GG3_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = GG3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedGG3_64(), composite, true);
	}

	@Test
	public void testGG3_64_speculative() throws Exception {
		CppCompositeType GG3_struct = createGG3_struct64(vbtManager64);
		GG3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = GG3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedGG3_64(), composite, true);
	}

	private String getExpectedGG3_64() {
		String expected =
		//@formatter:off
			"/GG3\n" + 
			"pack()\n" + 
			"Structure GG3 {\n" + 
			"   0   GG3_direct   16      \"\"\n" + 
			"   16   CC2_direct   4      \"(Virtual Base CC2)\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/GG3/GG3_direct\n" + 
			"pack()\n" + 
			"Structure GG3_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg31   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG3_64() {
		return convertCommentsToSpeculative(getExpectedGG3_64());
	}

	//==============================================================================================
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
	@Test
	public void testGG4_32_vbt() throws Exception {
		CppCompositeType GG4_struct = createGG4_struct32(pdbVbtManager32);
		GG4_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = GG4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedGG4_32(), composite, true);
	}

	@Test
	public void testGG4_32_speculative() throws Exception {
		CppCompositeType GG4_struct = createGG4_struct32(vbtManager32);
		GG4_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = GG4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedGG4_32(), composite, true);
	}

	private String getExpectedGG4_32() {
		String expected =
		//@formatter:off
			"/GG4\n" + 
			"pack()\n" + 
			"Structure GG4 {\n" + 
			"   0   GG4_direct   8      \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/GG4/GG4_direct\n" + 
			"pack()\n" + 
			"Structure GG4_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg41   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG4_32() {
		return convertCommentsToSpeculative(getExpectedGG4_32());
	}

	//==============================================================================================
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
	@Test
	public void testGG4_64_vbt() throws Exception {
		CppCompositeType GG4_struct = createGG4_struct64(pdbVbtManager64);
		GG4_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = GG4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedGG4_64(), composite, true);
	}

	@Test
	public void testGG4_64_speculative() throws Exception {
		CppCompositeType GG4_struct = createGG4_struct64(vbtManager64);
		GG4_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = GG4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedGG4_64(), composite, true);
	}

	private String getExpectedGG4_64() {
		String expected =
		//@formatter:off
			"/GG4\n" + 
			"pack()\n" + 
			"Structure GG4 {\n" + 
			"   0   GG4_direct   16      \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/GG4/GG4_direct\n" + 
			"pack()\n" + 
			"Structure GG4_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg41   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8";

		//@formatter:on
		return expected;
	}

	private String getSpeculatedGG4_64() {
		return convertCommentsToSpeculative(getExpectedGG4_64());
	}

	//==============================================================================================
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
	@Test
	public void testI_32_vbt() throws Exception {
		CppCompositeType I_struct = createI_struct32(pdbVbtManager32);
		I_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = I_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI_32(), composite, true);
	}

	@Test
	public void testI_32_speculative() throws Exception {
		CppCompositeType I_struct = createI_struct32(vbtManager32);
		I_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = I_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI_32(), composite, true);
	}

	private String getExpectedI_32() {
		String expected =
		//@formatter:off
			"/I\n" + 
			"pack()\n" + 
			"Structure I {\n" + 
			"   0   I_direct   20      \"\"\n" + 
			"   20   C_direct   4      \"(Virtual Base C)\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I/I_direct\n" + 
			"pack()\n" + 
			"Structure I_direct {\n" + 
			"   0   G_direct   8      \"\"\n" + 
			"   8   H_direct   8      \"\"\n" + 
			"   16   undefined4   4   i1   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI_32() {
		return convertCommentsToSpeculative(getExpectedI_32());
	}

	//==============================================================================================
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
	@Test
	public void testI_64_vbt() throws Exception {
		CppCompositeType I_struct = createI_struct64(pdbVbtManager64);
		I_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = I_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI_64(), composite, true);
	}

	@Test
	public void testI_64_speculative() throws Exception {
		CppCompositeType I_struct = createI_struct64(vbtManager64);
		I_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = I_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI_64(), composite, true);
	}

	private String getExpectedI_64() {
		String expected =
		//@formatter:off
			"/I\n" + 
			"pack()\n" + 
			"Structure I {\n" + 
			"   0   I_direct   40      \"\"\n" + 
			"   40   C_direct   4      \"(Virtual Base C)\"\n" + 
			"}\n" + 
			"Size = 48   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I/I_direct\n" + 
			"pack()\n" + 
			"Structure I_direct {\n" + 
			"   0   G_direct   16      \"\"\n" + 
			"   16   H_direct   16      \"\"\n" + 
			"   32   undefined4   4   i1   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI_64() {
		return convertCommentsToSpeculative(getExpectedI_64());
	}

	//==============================================================================================
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
	@Test
	public void testI1_32_vbt() throws Exception {
		CppCompositeType I1_struct = createI1_struct32(pdbVbtManager32);
		I1_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = I1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI1_32(), composite, true);
	}

	@Test
	public void testI1_32_speculative() throws Exception {
		CppCompositeType I1_struct = createI1_struct32(vbtManager32);
		I1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = I1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI1_32(), composite, true);
	}

	private String getExpectedI1_32() {
		String expected =
		//@formatter:off
			"/I1\n" + 
			"pack()\n" + 
			"Structure I1 {\n" + 
			"   0   I1_direct   20      \"\"\n" + 
			"   20   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   24   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 28   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I1/I1_direct\n" + 
			"pack()\n" + 
			"Structure I1_direct {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   H_direct   8      \"\"\n" + 
			"   16   undefined4   4   i11   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI1_32() {
		return convertCommentsToSpeculative(getExpectedI1_32());
	}

	//==============================================================================================
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
	@Test
	public void testI1_64_vbt() throws Exception {
		CppCompositeType I1_struct = createI1_struct64(pdbVbtManager64);
		I1_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = I1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI1_64(), composite, true);
	}

	@Test
	public void testI1_64_speculative() throws Exception {
		CppCompositeType I1_struct = createI1_struct64(vbtManager64);
		I1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = I1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI1_64(), composite, true);
	}

	private String getExpectedI1_64() {
		String expected =
		//@formatter:off
			"/I1\n" + 
			"pack()\n" + 
			"Structure I1 {\n" + 
			"   0   I1_direct   40      \"\"\n" + 
			"   40   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   44   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 48   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I1/I1_direct\n" + 
			"pack()\n" + 
			"Structure I1_direct {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   H_direct   16      \"\"\n" + 
			"   32   undefined4   4   i11   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI1_64() {
		return convertCommentsToSpeculative(getExpectedI1_64());
	}

	//==============================================================================================
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
	@Test
	public void testI2_32_vbt() throws Exception {
		CppCompositeType I2_struct = createI2_struct32(pdbVbtManager32);
		I2_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = I2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI2_32(), composite, true);
	}

	@Test
	public void testI2_32_speculative() throws Exception {
		CppCompositeType I2_struct = createI2_struct32(vbtManager32);
		I2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = I2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI2_32(), composite, true);
	}

	private String getExpectedI2_32() {
		String expected =
		//@formatter:off
			"/I2\n" + 
			"pack()\n" + 
			"Structure I2 {\n" + 
			"   0   I2_direct   20      \"\"\n" + 
			"   20   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   24   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 28   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I2/I2_direct\n" + 
			"pack()\n" + 
			"Structure I2_direct {\n" + 
			"   0   G_direct   8      \"\"\n" + 
			"   8   H1_direct   8      \"\"\n" + 
			"   16   undefined4   4   i21   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI2_32() {
		return convertCommentsToSpeculative(getExpectedI2_32());
	}

	//==============================================================================================
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
	@Test
	public void testI2_64_vbt() throws Exception {
		CppCompositeType I2_struct = createI2_struct64(pdbVbtManager64);
		I2_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = I2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI2_64(), composite, true);
	}

	@Test
	public void testI2_64_speculative() throws Exception {
		CppCompositeType I2_struct = createI2_struct64(vbtManager64);
		I2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = I2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI2_64(), composite, true);
	}

	private String getExpectedI2_64() {
		String expected =
		//@formatter:off
			"/I2\n" + 
			"pack()\n" + 
			"Structure I2 {\n" + 
			"   0   I2_direct   40      \"\"\n" + 
			"   40   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   44   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 48   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I2/I2_direct\n" + 
			"pack()\n" + 
			"Structure I2_direct {\n" + 
			"   0   G_direct   16      \"\"\n" + 
			"   16   H1_direct   16      \"\"\n" + 
			"   32   undefined4   4   i21   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI2_64() {
		return convertCommentsToSpeculative(getExpectedI2_64());
	}

	//==============================================================================================
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
	@Test
	public void testI3_32_vbt() throws Exception {
		CppCompositeType I3_struct = createI3_struct32(pdbVbtManager32);
		I3_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = I3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI3_32(), composite, true);
	}

	@Test
	public void testI3_32_speculative() throws Exception {
		CppCompositeType I3_struct = createI3_struct32(vbtManager32);
		I3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = I3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI3_32(), composite, true);
	}

	private String getExpectedI3_32() {
		String expected =
		//@formatter:off
			"/I3\n" + 
			"pack()\n" + 
			"Structure I3 {\n" + 
			"   0   I3_direct   20      \"\"\n" + 
			"   20   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   24   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 28   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I3/I3_direct\n" + 
			"pack()\n" + 
			"Structure I3_direct {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   H1_direct   8      \"\"\n" + 
			"   16   undefined4   4   i31   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI3_32() {
		return convertCommentsToSpeculative(getExpectedI3_32());
	}

	//==============================================================================================
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
	@Test
	public void testI3_64_vbt() throws Exception {
		CppCompositeType I3_struct = createI3_struct64(pdbVbtManager64);
		I3_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = I3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI3_64(), composite, true);
	}

	@Test
	public void testI3_64_speculative() throws Exception {
		CppCompositeType I3_struct = createI3_struct64(vbtManager64);
		I3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = I3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI3_64(), composite, true);
	}

	private String getExpectedI3_64() {
		String expected =
		//@formatter:off
			"/I3\n" + 
			"pack()\n" + 
			"Structure I3 {\n" + 
			"   0   I3_direct   40      \"\"\n" + 
			"   40   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   44   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 48   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I3/I3_direct\n" + 
			"pack()\n" + 
			"Structure I3_direct {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   H1_direct   16      \"\"\n" + 
			"   32   undefined4   4   i31   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI3_64() {
		return convertCommentsToSpeculative(getExpectedI3_64());
	}

	//==============================================================================================
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
	@Test
	public void testI4_32_vbt() throws Exception {
		CppCompositeType I4_struct = createI4_struct32(pdbVbtManager32);
		I4_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = I4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI4_32(), composite, true);
	}

	@Test
	public void testI4_32_speculative() throws Exception {
		CppCompositeType I4_struct = createI4_struct32(vbtManager32);
		I4_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = I4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI4_32(), composite, true);
	}

	private String getExpectedI4_32() {
		String expected =
		//@formatter:off
			"/I4\n" + 
			"pack()\n" + 
			"Structure I4 {\n" + 
			"   0   I4_direct   12      \"\"\n" + 
			"   12   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   16   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I4/I4_direct\n" + 
			"pack()\n" + 
			"Structure I4_direct {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   undefined4   4   i41   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4";

		//@formatter:on
		return expected;
	}

	private String getSpeculatedI4_32() {
		return convertCommentsToSpeculative(getExpectedI4_32());
	}

	//==============================================================================================
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
	@Test
	public void testI4_64_vbt() throws Exception {
		CppCompositeType I4_struct = createI4_struct64(pdbVbtManager64);
		I4_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = I4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI4_64(), composite, true);
	}

	@Test
	public void testI4_64_speculative() throws Exception {
		CppCompositeType I4_struct = createI4_struct64(vbtManager64);
		I4_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = I4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI4_64(), composite, true);
	}

	private String getExpectedI4_64() {
		String expected =
		//@formatter:off
			"/I4\n" + 
			"pack()\n" + 
			"Structure I4 {\n" + 
			"   0   I4_direct   24      \"\"\n" + 
			"   24   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   28   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 32   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I4/I4_direct\n" + 
			"pack()\n" + 
			"Structure I4_direct {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   undefined4   4   i41   \"\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedI4_64() {
		return convertCommentsToSpeculative(getExpectedI4_64());
	}

	//==============================================================================================
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
	@Test
	public void testI5_32_vbt() throws Exception {
		CppCompositeType I5_struct = createI5_struct32(pdbVbtManager32);
		I5_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = I5_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedtI5_32(), composite, true);
	}

	@Test
	public void testI5_32_speculative() throws Exception {
		CppCompositeType I5_struct = createI5_struct32(vbtManager32);
		I5_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = I5_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedtI5_32(), composite, true);
	}

	private String getExpectedtI5_32() {
		String expected =
		//@formatter:off
			"/I5\n" + 
			"pack()\n" + 
			"Structure I5 {\n" + 
			"   0   I5_direct   12      \"\"\n" + 
			"   12   E_direct   4      \"(Virtual Base E)\"\n" + 
			"   16   C_direct   4      \"(Virtual Base C)\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I5/I5_direct\n" + 
			"pack()\n" + 
			"Structure I5_direct {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   undefined4   4   i51   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	// NOTE: We know that this is an incorrect layout (it matches that of I4), but we are
	//  measuring our result against the best we can determine (C and E virtual bases are
	//  switched from the actual as the Base Class records in the PDB are given in the exact
	//  same order as for I4.  Using the VBT-based algorithm can produce the correct layout, but
	//  the speculative algorithm works without it.
	private String getSpeculatedtI5_32() {
		String expected =
		//@formatter:off
			"/I5\n" + 
			"pack()\n" + 
			"Structure I5 {\n" + 
			"   0   I5_direct   12      \"\"\n" + 
			"   12   C_direct   4      \"((Speculative Placement) Virtual Base C)\"\n" + 
			"   16   E_direct   4      \"((Speculative Placement) Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I5/I5_direct\n" + 
			"pack()\n" + 
			"Structure I5_direct {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   undefined4   4   i51   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	//==============================================================================================
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
	@Test
	public void testI5_64_vbt() throws Exception {
		CppCompositeType I5_struct = createI5_struct64(pdbVbtManager64);
		I5_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = I5_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedI5_64(), composite, true);
	}

	@Test
	public void testI5_64_speculative() throws Exception {
		CppCompositeType I5_struct = createI5_struct64(vbtManager64);
		I5_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = I5_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedI5_64(), composite, true);
	}

	private String getExpectedI5_64() {
		String expected =
		//@formatter:off
			"/I5\n" + 
			"pack()\n" + 
			"Structure I5 {\n" + 
			"   0   I5_direct   24      \"\"\n" + 
			"   24   E_direct   4      \"(Virtual Base E)\"\n" + 
			"   28   C_direct   4      \"(Virtual Base C)\"\n" + 
			"}\n" + 
			"Size = 32   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I5/I5_direct\n" + 
			"pack()\n" + 
			"Structure I5_direct {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   undefined4   4   i51   \"\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	// NOTE: We know that this is an incorrect layout (it matches that of I4), but we are
	//  measuring our result against the best we can determine (C and E virtual bases are
	//  switched from the actual as the Base Class records in the PDB are given in the exact
	//  same order as for I4.  Using the VBT-based algorithm can produce the correct layout, but
	//  the speculative algorithm works without it.
	private String getSpeculatedI5_64() {
		String expected =
		//@formatter:off
			"/I5\n" + 
			"pack()\n" + 
			"Structure I5 {\n" + 
			"   0   I5_direct   24      \"\"\n" + 
			"   24   C_direct   4      \"((Speculative Placement) Virtual Base C)\"\n" + 
			"   28   E_direct   4      \"((Speculative Placement) Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 32   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I5/I5_direct\n" + 
			"pack()\n" + 
			"Structure I5_direct {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   undefined4   4   i51   \"\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	//==============================================================================================
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
	@Test
	public void testJ1_32_vbt() throws Exception {
		CppCompositeType J1_struct = createJ1_struct32(pdbVbtManager32);
		J1_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = J1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ1_32(), composite, true);
	}

	@Test
	public void testJ1_32_speculative() throws Exception {
		CppCompositeType J1_struct = createJ1_struct32(vbtManager32);
		J1_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = J1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ1_32(), composite, true);
	}

	private String getExpectedJ1_32() {
		String expected =
		//@formatter:off
			"/J1\n" + 
			"pack()\n" + 
			"Structure J1 {\n" + 
			"   0   J1_direct   44      \"\"\n" + 
			"   44   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   48   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 52   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I1/I1_direct\n" + 
			"pack()\n" + 
			"Structure I1_direct {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   H_direct   8      \"\"\n" + 
			"   16   undefined4   4   i11   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/I2/I2_direct\n" + 
			"pack()\n" + 
			"Structure I2_direct {\n" + 
			"   0   G_direct   8      \"\"\n" + 
			"   8   H1_direct   8      \"\"\n" + 
			"   16   undefined4   4   i21   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/J1/J1_direct\n" + 
			"pack()\n" + 
			"Structure J1_direct {\n" + 
			"   0   I1_direct   20      \"\"\n" + 
			"   20   I2_direct   20      \"\"\n" + 
			"   40   undefined4   4   j11   \"\"\n" + 
			"}\n" + 
			"Size = 44   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ1_32() {
		return convertCommentsToSpeculative(getExpectedJ1_32());
	}

	//==============================================================================================
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
	@Test
	public void testJ1_64_vbt() throws Exception {
		CppCompositeType J1_struct = createJ1_struct64(pdbVbtManager64);
		J1_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = J1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ1_64(), composite, true);
	}

	@Test
	public void testJ1_64_speculative() throws Exception {
		CppCompositeType J1_struct = createJ1_struct64(vbtManager64);
		J1_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = J1_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ1_64(), composite, true);
	}

	private String getExpectedJ1_64() {
		String expected =
		//@formatter:off
			"/J1\n" + 
			"pack()\n" + 
			"Structure J1 {\n" + 
			"   0   J1_direct   88      \"\"\n" + 
			"   88   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   92   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 96   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I1/I1_direct\n" + 
			"pack()\n" + 
			"Structure I1_direct {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   H_direct   16      \"\"\n" + 
			"   32   undefined4   4   i11   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8\n" + 
			"/I2/I2_direct\n" + 
			"pack()\n" + 
			"Structure I2_direct {\n" + 
			"   0   G_direct   16      \"\"\n" + 
			"   16   H1_direct   16      \"\"\n" + 
			"   32   undefined4   4   i21   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8\n" + 
			"/J1/J1_direct\n" + 
			"pack()\n" + 
			"Structure J1_direct {\n" + 
			"   0   I1_direct   40      \"\"\n" + 
			"   40   I2_direct   40      \"\"\n" + 
			"   80   undefined4   4   j11   \"\"\n" + 
			"}\n" + 
			"Size = 88   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ1_64() {
		return convertCommentsToSpeculative(getExpectedJ1_64());
	}

	//==============================================================================================
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
	@Test
	public void testJ2_32_vbt() throws Exception {
		CppCompositeType J2_struct = createJ2_struct32(pdbVbtManager32);
		J2_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = J2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ2_32(), composite, true);
	}

	@Test
	public void testJ2_32_speculative() throws Exception {
		CppCompositeType J2_struct = createJ2_struct32(vbtManager32);
		J2_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = J2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ2_32(), composite, true);
	}

	private String getExpectedJ2_32() {
		String expected =
		//@formatter:off
			"/J2\n" + 
			"pack()\n" + 
			"Structure J2 {\n" + 
			"   0   J2_direct   44      \"\"\n" + 
			"   44   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   48   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 52   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I1/I1_direct\n" + 
			"pack()\n" + 
			"Structure I1_direct {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   H_direct   8      \"\"\n" + 
			"   16   undefined4   4   i11   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/I2/I2_direct\n" + 
			"pack()\n" + 
			"Structure I2_direct {\n" + 
			"   0   G_direct   8      \"\"\n" + 
			"   8   H1_direct   8      \"\"\n" + 
			"   16   undefined4   4   i21   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/J2/J2_direct\n" + 
			"pack()\n" + 
			"Structure J2_direct {\n" + 
			"   0   I2_direct   20      \"\"\n" + 
			"   20   I1_direct   20      \"\"\n" + 
			"   40   undefined4   4   j21   \"\"\n" + 
			"}\n" + 
			"Size = 44   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ2_32() {
		return convertCommentsToSpeculative(getExpectedJ2_32());
	}

	//==============================================================================================
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
	@Test
	public void testJ2_64_vbt() throws Exception {
		CppCompositeType J2_struct = createJ2_struct64(pdbVbtManager64);
		J2_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = J2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ2_64(), composite, true);
	}

	@Test
	public void testJ2_64_speculative() throws Exception {
		CppCompositeType J2_struct = createJ2_struct64(vbtManager64);
		J2_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = J2_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ2_64(), composite, true);
	}

	private String getExpectedJ2_64() {
		String expected =
		//@formatter:off
			"/J2\n" + 
			"pack()\n" + 
			"Structure J2 {\n" + 
			"   0   J2_direct   88      \"\"\n" + 
			"   88   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   92   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 96   Actual Alignment = 8\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I1/I1_direct\n" + 
			"pack()\n" + 
			"Structure I1_direct {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   H_direct   16      \"\"\n" + 
			"   32   undefined4   4   i11   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8\n" + 
			"/I2/I2_direct\n" + 
			"pack()\n" + 
			"Structure I2_direct {\n" + 
			"   0   G_direct   16      \"\"\n" + 
			"   16   H1_direct   16      \"\"\n" + 
			"   32   undefined4   4   i21   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8\n" + 
			"/J2/J2_direct\n" + 
			"pack()\n" + 
			"Structure J2_direct {\n" + 
			"   0   I2_direct   40      \"\"\n" + 
			"   40   I1_direct   40      \"\"\n" + 
			"   80   undefined4   4   j21   \"\"\n" + 
			"}\n" + 
			"Size = 88   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ2_64() {
		return convertCommentsToSpeculative(getExpectedJ2_64());
	}

	//==============================================================================================
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
	@Test
	public void testJ3_32_vbt() throws Exception {
		CppCompositeType J3_struct = createJ3_struct32(pdbVbtManager32);
		J3_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = J3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ3_32(), composite, true);
	}

	@Test
	public void testJ3_32_speculative() throws Exception {
		CppCompositeType J3_struct = createJ3_struct32(vbtManager32);
		J3_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = J3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ3_32(), composite, true);
	}

	private String getExpectedJ3_32() {
		String expected =
		//@formatter:off
			"/J3\n" + 
			"pack()\n" + 
			"Structure J3 {\n" + 
			"   0   J3_direct   52      \"\"\n" + 
			"   52   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   56   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 60   Actual Alignment = 4\n" + 
			"/A/A_direct\n" + 
			"pack()\n" + 
			"Structure A_direct {\n" + 
			"   0   undefined1   1   c   \"\"\n" + 
			"   4   undefined4   4   i   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I1/I1_direct\n" + 
			"pack()\n" + 
			"Structure I1_direct {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   H_direct   8      \"\"\n" + 
			"   16   undefined4   4   i11   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/I2/I2_direct\n" + 
			"pack()\n" + 
			"Structure I2_direct {\n" + 
			"   0   G_direct   8      \"\"\n" + 
			"   8   H1_direct   8      \"\"\n" + 
			"   16   undefined4   4   i21   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/J3/J3_direct\n" + 
			"pack()\n" + 
			"Structure J3_direct {\n" + 
			"   0   I2_direct   20      \"\"\n" + 
			"   20   I1_direct   20      \"\"\n" + 
			"   40   A_direct   8      \"\"\n" + 
			"   48   undefined4   4   j31   \"\"\n" + 
			"}\n" + 
			"Size = 52   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ3_32() {
		return convertCommentsToSpeculative(getExpectedJ3_32());
	}

	//==============================================================================================
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
	@Test
	public void testJ3_64_vbt() throws Exception {
		CppCompositeType J3_struct = createJ3_struct64(pdbVbtManager64);
		J3_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = J3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ3_64(), composite, true);
	}

	@Test
	public void testJ3_64_speculative() throws Exception {
		CppCompositeType J3_struct = createJ3_struct64(vbtManager64);
		J3_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = J3_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ3_64(), composite, true);
	}

	private String getExpectedJ3_64() {
		String expected =
		//@formatter:off
			"/J3\n" + 
			"pack()\n" + 
			"Structure J3 {\n" + 
			"   0   J3_direct   96      \"\"\n" + 
			"   96   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   100   E_direct   4      \"(Virtual Base E)\"\n" + 
			"}\n" + 
			"Size = 104   Actual Alignment = 8\n" + 
			"/A/A_direct\n" + 
			"pack()\n" + 
			"Structure A_direct {\n" + 
			"   0   undefined1   1   c   \"\"\n" + 
			"   4   undefined4   4   i   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I1/I1_direct\n" + 
			"pack()\n" + 
			"Structure I1_direct {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   H_direct   16      \"\"\n" + 
			"   32   undefined4   4   i11   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8\n" + 
			"/I2/I2_direct\n" + 
			"pack()\n" + 
			"Structure I2_direct {\n" + 
			"   0   G_direct   16      \"\"\n" + 
			"   16   H1_direct   16      \"\"\n" + 
			"   32   undefined4   4   i21   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8\n" + 
			"/J3/J3_direct\n" + 
			"pack()\n" + 
			"Structure J3_direct {\n" + 
			"   0   I2_direct   40      \"\"\n" + 
			"   40   I1_direct   40      \"\"\n" + 
			"   80   A_direct   8      \"\"\n" + 
			"   88   undefined4   4   j31   \"\"\n" + 
			"}\n" + 
			"Size = 96   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ3_64() {
		return convertCommentsToSpeculative(getExpectedJ3_64());
	}

	//==============================================================================================
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
	@Test
	public void testJ4_32_vbt() throws Exception {
		CppCompositeType J4_struct = createJ4_struct32(pdbVbtManager32);
		J4_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = J4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ4_32(), composite, true);
	}

	@Test
	public void testJ4_32_speculative() throws Exception {
		CppCompositeType J4_struct = createJ4_struct32(vbtManager32);
		J4_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = J4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ4_32(), composite, true);
	}

	private String getExpectedJ4_32() {
		String expected =
		//@formatter:off
			"/J4\n" + 
			"pack()\n" + 
			"Structure J4 {\n" + 
			"   0   J4_direct   60      \"\"\n" + 
			"   60   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   64   E_direct   4      \"(Virtual Base E)\"\n" + 
			"   68   CC1_direct   4      \"(Virtual Base CC1)\"\n" + 
			"   72   CC2_direct   4      \"(Virtual Base CC2)\"\n" + 
			"   76   GG2_direct   8      \"(Virtual Base GG2)\"\n" + 
			"   84   GG3_direct   8      \"(Virtual Base GG3)\"\n" + 
			"}\n" + 
			"Size = 92   Actual Alignment = 4\n" + 
			"/A/A_direct\n" + 
			"pack()\n" + 
			"Structure A_direct {\n" + 
			"   0   undefined1   1   c   \"\"\n" + 
			"   4   undefined4   4   i   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC1/CC1_direct\n" + 
			"pack()\n" + 
			"Structure CC1_direct {\n" + 
			"   0   undefined4   4   cc11   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/GG1/GG1_direct\n" + 
			"pack()\n" + 
			"Structure GG1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/GG2/GG2_direct\n" + 
			"pack()\n" + 
			"Structure GG2_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg21   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/GG3/GG3_direct\n" + 
			"pack()\n" + 
			"Structure GG3_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg31   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I/I_direct\n" + 
			"pack()\n" + 
			"Structure I_direct {\n" + 
			"   0   G_direct   8      \"\"\n" + 
			"   8   H_direct   8      \"\"\n" + 
			"   16   undefined4   4   i1   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/I3/I3_direct\n" + 
			"pack()\n" + 
			"Structure I3_direct {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   H1_direct   8      \"\"\n" + 
			"   16   undefined4   4   i31   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/J4/J4_direct\n" + 
			"pack()\n" + 
			"Structure J4_direct {\n" + 
			"   0   I3_direct   20      \"\"\n" + 
			"   20   GG1_direct   8      \"\"\n" + 
			"   28   I_direct   20      \"\"\n" + 
			"   48   A_direct   8      \"\"\n" + 
			"   56   undefined4   4   j41   \"\"\n" + 
			"}\n" + 
			"Size = 60   Actual Alignment = 4";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ4_32() {
		return convertCommentsToSpeculative(getExpectedJ4_32());
	}

	//==============================================================================================
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
	@Test
	public void testJ4_64_vbt() throws Exception {
		CppCompositeType J4_struct = createJ4_struct64(pdbVbtManager64);
		J4_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = J4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ4_64(), composite, true);
	}

	@Test
	public void testJ4_64_speculative() throws Exception {
		CppCompositeType J4_struct = createJ4_struct64(vbtManager64);
		J4_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = J4_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ4_64(), composite, true);
	}

	private String getExpectedJ4_64() {
		String expected =
		//@formatter:off
			"/J4\n" + 
			"pack()\n" + 
			"Structure J4 {\n" + 
			"   0   J4_direct   112      \"\"\n" + 
			"   112   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   116   E_direct   4      \"(Virtual Base E)\"\n" + 
			"   120   CC1_direct   4      \"(Virtual Base CC1)\"\n" + 
			"   124   CC2_direct   4      \"(Virtual Base CC2)\"\n" + 
			"   128   GG2_direct   16      \"(Virtual Base GG2)\"\n" + 
			"   144   GG3_direct   16      \"(Virtual Base GG3)\"\n" + 
			"}\n" + 
			"Size = 160   Actual Alignment = 8\n" + 
			"/A/A_direct\n" + 
			"pack()\n" + 
			"Structure A_direct {\n" + 
			"   0   undefined1   1   c   \"\"\n" + 
			"   4   undefined4   4   i   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC1/CC1_direct\n" + 
			"pack()\n" + 
			"Structure CC1_direct {\n" + 
			"   0   undefined4   4   cc11   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/GG1/GG1_direct\n" + 
			"pack()\n" + 
			"Structure GG1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/GG2/GG2_direct\n" + 
			"pack()\n" + 
			"Structure GG2_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg21   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/GG3/GG3_direct\n" + 
			"pack()\n" + 
			"Structure GG3_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg31   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I/I_direct\n" + 
			"pack()\n" + 
			"Structure I_direct {\n" + 
			"   0   G_direct   16      \"\"\n" + 
			"   16   H_direct   16      \"\"\n" + 
			"   32   undefined4   4   i1   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8\n" + 
			"/I3/I3_direct\n" + 
			"pack()\n" + 
			"Structure I3_direct {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   H1_direct   16      \"\"\n" + 
			"   32   undefined4   4   i31   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8\n" + 
			"/J4/J4_direct\n" + 
			"pack()\n" + 
			"Structure J4_direct {\n" + 
			"   0   I3_direct   40      \"\"\n" + 
			"   40   GG1_direct   16      \"\"\n" + 
			"   56   I_direct   40      \"\"\n" + 
			"   96   A_direct   8      \"\"\n" + 
			"   104   undefined4   4   j41   \"\"\n" + 
			"}\n" + 
			"Size = 112   Actual Alignment = 8";
		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ4_64() {
		return convertCommentsToSpeculative(getExpectedJ4_64());
	}

	//==============================================================================================
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
	@Test
	public void testJ5_32_vbt() throws Exception {
		CppCompositeType J5_struct = createJ5_struct32(pdbVbtManager32);
		J5_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = J5_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ5_32(), composite, true);
	}

	// TODO: Need to work on layout algorithm... believe we can do better, but don't have
	//  a decision on the best speculative results yet.
//	@Test
	public void testJ5_32_speculative() throws Exception {
		CppCompositeType J5_struct = createJ5_struct32(vbtManager32);
		J5_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = J5_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ5_32(), composite, true);
	}

	private String getExpectedJ5_32() {
		String expected =
		//@formatter:off
			"/J5\n" + 
			"pack()\n" + 
			"Structure J5 {\n" + 
			"   0   J5_direct   60      \"\"\n" + 
			"   60   CC2_direct   4      \"(Virtual Base CC2)\"\n" + 
			"   64   GG2_direct   8      \"(Virtual Base GG2)\"\n" + 
			"   72   GG3_direct   8      \"(Virtual Base GG3)\"\n" + 
			"   80   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   84   E_direct   4      \"(Virtual Base E)\"\n" + 
			"   88   CC1_direct   4      \"(Virtual Base CC1)\"\n" + 
			"}\n" + 
			"Size = 92   Actual Alignment = 4\n" + 
			"/A/A_direct\n" + 
			"pack()\n" + 
			"Structure A_direct {\n" + 
			"   0   undefined1   1   c   \"\"\n" + 
			"   4   undefined4   4   i   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC1/CC1_direct\n" + 
			"pack()\n" + 
			"Structure CC1_direct {\n" + 
			"   0   undefined4   4   cc11   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/GG1/GG1_direct\n" + 
			"pack()\n" + 
			"Structure GG1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/GG2/GG2_direct\n" + 
			"pack()\n" + 
			"Structure GG2_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg21   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/GG3/GG3_direct\n" + 
			"pack()\n" + 
			"Structure GG3_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg31   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/I/I_direct\n" + 
			"pack()\n" + 
			"Structure I_direct {\n" + 
			"   0   G_direct   8      \"\"\n" + 
			"   8   H_direct   8      \"\"\n" + 
			"   16   undefined4   4   i1   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/I3/I3_direct\n" + 
			"pack()\n" + 
			"Structure I3_direct {\n" + 
			"   0   G1_direct   8      \"\"\n" + 
			"   8   H1_direct   8      \"\"\n" + 
			"   16   undefined4   4   i31   \"\"\n" + 
			"}\n" + 
			"Size = 20   Actual Alignment = 4\n" + 
			"/J5/J5_direct\n" + 
			"pack()\n" + 
			"Structure J5_direct {\n" + 
			"   0   I3_direct   20      \"\"\n" + 
			"   20   GG1_direct   8      \"\"\n" + 
			"   28   I_direct   20      \"\"\n" + 
			"   48   A_direct   8      \"\"\n" + 
			"   56   undefined4   4   j51   \"\"\n" + 
			"}\n" + 
			"Size = 60   Actual Alignment = 4";

		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ5_32() {
		String expected =
		//@formatter:off
			"NOT YET DETERMINED";
		//@formatter:on
		return expected;
	}

	//==============================================================================================
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
	@Test
	public void testJ5_64_vbt() throws Exception {
		CppCompositeType J5_struct = createJ5_struct64(pdbVbtManager64);
		J5_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = J5_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ5_64(), composite, true);
	}

	// TODO: Need to work on layout algorithm... believe we can do better, but don't have
	//  a decision on the best speculative results yet.
//	@Test
	public void testJ5_64_speculative() throws Exception {
		CppCompositeType J5_struct = createJ5_struct64(vbtManager64);
		J5_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = J5_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ5_64(), composite, true);
	}

	private String getExpectedJ5_64() {
		String expected =
		//@formatter:off
			"/J5\n" + 
			"pack()\n" + 
			"Structure J5 {\n" + 
			"   0   J5_direct   112      \"\"\n" + 
			"   112   CC2_direct   4      \"(Virtual Base CC2)\"\n" + 
			"   120   GG2_direct   16      \"(Virtual Base GG2)\"\n" + 
			"   136   GG3_direct   16      \"(Virtual Base GG3)\"\n" + 
			"   152   C_direct   4      \"(Virtual Base C)\"\n" + 
			"   156   E_direct   4      \"(Virtual Base E)\"\n" + 
			"   160   CC1_direct   4      \"(Virtual Base CC1)\"\n" + 
			"}\n" + 
			"Size = 168   Actual Alignment = 8\n" + 
			"/A/A_direct\n" + 
			"pack()\n" + 
			"Structure A_direct {\n" + 
			"   0   undefined1   1   c   \"\"\n" + 
			"   4   undefined4   4   i   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/C/C_direct\n" + 
			"pack()\n" + 
			"Structure C_direct {\n" + 
			"   0   undefined4   4   c1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC1/CC1_direct\n" + 
			"pack()\n" + 
			"Structure CC1_direct {\n" + 
			"   0   undefined4   4   cc11   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/E/E_direct\n" + 
			"pack()\n" + 
			"Structure E_direct {\n" + 
			"   0   undefined4   4   e1   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/G/G_direct\n" + 
			"pack()\n" + 
			"Structure G_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/G1/G1_direct\n" + 
			"pack()\n" + 
			"Structure G1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   g11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/GG1/GG1_direct\n" + 
			"pack()\n" + 
			"Structure GG1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/GG2/GG2_direct\n" + 
			"pack()\n" + 
			"Structure GG2_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg21   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/GG3/GG3_direct\n" + 
			"pack()\n" + 
			"Structure GG3_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg31   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H/H_direct\n" + 
			"pack()\n" + 
			"Structure H_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h1   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/H1/H1_direct\n" + 
			"pack()\n" + 
			"Structure H1_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   h11   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/I/I_direct\n" + 
			"pack()\n" + 
			"Structure I_direct {\n" + 
			"   0   G_direct   16      \"\"\n" + 
			"   16   H_direct   16      \"\"\n" + 
			"   32   undefined4   4   i1   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8\n" + 
			"/I3/I3_direct\n" + 
			"pack()\n" + 
			"Structure I3_direct {\n" + 
			"   0   G1_direct   16      \"\"\n" + 
			"   16   H1_direct   16      \"\"\n" + 
			"   32   undefined4   4   i31   \"\"\n" + 
			"}\n" + 
			"Size = 40   Actual Alignment = 8\n" + 
			"/J5/J5_direct\n" + 
			"pack()\n" + 
			"Structure J5_direct {\n" + 
			"   0   I3_direct   40      \"\"\n" + 
			"   40   GG1_direct   16      \"\"\n" + 
			"   56   I_direct   40      \"\"\n" + 
			"   96   A_direct   8      \"\"\n" + 
			"   104   undefined4   4   j51   \"\"\n" + 
			"}\n" + 
			"Size = 112   Actual Alignment = 8";

		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ5_64() {
		String expected =
		//@formatter:off
			"NOT YET DETERMINED";
		//@formatter:on
		return expected;
	}

	//==============================================================================================
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
	@Test
	public void testJ6_32_vbt() throws Exception {
		CppCompositeType J6_struct = createJ6_struct32(pdbVbtManager32);
		J6_struct.createLayout(classLayoutChoice, pdbVbtManager32, TaskMonitor.DUMMY);
		Composite composite = J6_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ6_32(), composite, true);
	}

	// TODO: Need to work on layout algorithm... believe we can do better, but don't have
	//  a decision on the best speculative results yet.
//	@Test
	public void testJ6_32_speculative() throws Exception {
		CppCompositeType J6_struct = createJ6_struct32(vbtManager32);
		J6_struct.createLayout(classLayoutChoice, vbtManager32, TaskMonitor.DUMMY);
		Composite composite = J6_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ6_32(), composite, true);
	}

	private String getExpectedJ6_32() {
		String expected =
		//@formatter:off
			"/J6\n" + 
			"pack()\n" + 
			"Structure J6 {\n" + 
			"   0   J6_direct   16      \"\"\n" + 
			"   16   GG4_direct   8      \"(Virtual Base GG4)\"\n" + 
			"   24   CC2_direct   4      \"(Virtual Base (empty) CC3)(Virtual Base CC2)\"\n" + 
			"   28   GG3_direct   8      \"(Virtual Base GG3)\"\n" + 
			"}\n" + 
			"Size = 36   Actual Alignment = 4\n" + 
			"/A/A_direct\n" + 
			"pack()\n" + 
			"Structure A_direct {\n" + 
			"   0   undefined1   1   c   \"\"\n" + 
			"   4   undefined4   4   i   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/GG3/GG3_direct\n" + 
			"pack()\n" + 
			"Structure GG3_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg31   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/GG4/GG4_direct\n" + 
			"pack()\n" + 
			"Structure GG4_direct {\n" + 
			"   0   int *   4   {vbptr}   \"\"\n" + 
			"   4   undefined4   4   gg41   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/J6/J6_direct\n" + 
			"pack()\n" + 
			"Structure J6_direct {\n" + 
			"   0   A_direct   8      \"\"\n" + 
			"   8   int *   4   {vbptr}   \"\"\n" + 
			"   12   undefined4   4   j61   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 4";

		//@formatter:on
		return expected;
	}

	private String getSpeculatedJ6_32() {
		String expected =
		//@formatter:off
			"NOT YET DETERMINED";
		//@formatter:on
		return expected;
	}

	//==============================================================================================
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
	@Test
	public void testJ6_64_vbt() throws Exception {
		CppCompositeType J6_struct = createJ6_struct64(pdbVbtManager64);
		J6_struct.createLayout(classLayoutChoice, pdbVbtManager64, TaskMonitor.DUMMY);
		Composite composite = J6_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getExpectedJ6_64(), composite, true);
	}

	// TODO: Need to work on layout algorithm... believe we can do better, but don't have
	//  a decision on the best speculative results yet.
//	@Test
	public void testJ6_64_speculative() throws Exception {
		CppCompositeType J6_struct = createJ6_struct64(vbtManager64);
		J6_struct.createLayout(classLayoutChoice, vbtManager64, TaskMonitor.DUMMY);
		Composite composite = J6_struct.getComposite();
		CompositeTestUtils.assertExpectedComposite(this, getSpeculatedJ6_64(), composite, true);
	}

	private String getExpectedJ6_64() {
		String expected =
		//@formatter:off
			"/J6\n" + 
			"pack()\n" + 
			"Structure J6 {\n" + 
			"   0   J6_direct   24      \"\"\n" + 
			"   24   GG4_direct   16      \"(Virtual Base GG4)\"\n" + 
			"   40   CC2_direct   4      \"(Virtual Base (empty) CC3)(Virtual Base CC2)\"\n" + 
			"   48   GG3_direct   16      \"(Virtual Base GG3)\"\n" + 
			"}\n" + 
			"Size = 64   Actual Alignment = 8\n" + 
			"/A/A_direct\n" + 
			"pack()\n" + 
			"Structure A_direct {\n" + 
			"   0   undefined1   1   c   \"\"\n" + 
			"   4   undefined4   4   i   \"\"\n" + 
			"}\n" + 
			"Size = 8   Actual Alignment = 4\n" + 
			"/CC2/CC2_direct\n" + 
			"pack()\n" + 
			"Structure CC2_direct {\n" + 
			"   0   undefined4   4   cc21   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4\n" + 
			"/GG3/GG3_direct\n" + 
			"pack()\n" + 
			"Structure GG3_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg31   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/GG4/GG4_direct\n" + 
			"pack()\n" + 
			"Structure GG4_direct {\n" + 
			"   0   int *   8   {vbptr}   \"\"\n" + 
			"   8   undefined4   4   gg41   \"\"\n" + 
			"}\n" + 
			"Size = 16   Actual Alignment = 8\n" + 
			"/J6/J6_direct\n" + 
			"pack()\n" + 
			"Structure J6_direct {\n" + 
			"   0   A_direct   8      \"\"\n" + 
			"   8   int *   8   {vbptr}   \"\"\n" + 
			"   16   undefined4   4   j61   \"\"\n" + 
			"}\n" + 
			"Size = 24   Actual Alignment = 8";

		//@formatter:on
		return expected;
	}

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

//	@Test
	@Ignore
	public void testJ5_32_syntactic_layout() throws Exception {
		CppCompositeType J5_struct = createJ5_syntactic_struct32(pdbVbtManager32);
		J5_struct.createLayoutFromSyntacticDescription(pdbVbtManager32, TaskMonitor.DUMMY);
		//
		//Composite composite = J5_struct.getComposite();
		//CompositeTestUtils.assertExpectedComposite(this, getExpectedJ5_32(), composite, true);
	}

}
