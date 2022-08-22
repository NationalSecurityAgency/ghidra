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
package ghidra.app.util.datatype.microsoft;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;

import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

/**
 * Class for creating a Ghidra memory block representing the TEB: Thread Environment Block.
 * The class must be instantiated with the Program and the Windows OS version to control
 * details of the TEB layout.  The user must call setAddress to provide the starting address
 * of the block to create. Then they must call one of
 *    - createBlockAndStructure    or
 *    - createBlocksAndSymbols
 * 
 * The TEB can be represented either by a single structure overlaying the
 * block (createBlockAndStructure), or as a series of symbols and primitive
 * data-types (createBlocksAndSymbols).
 * 
 * Finally the user should call setRegisterValue. The TEB is accessed either through the FS segment
 * (32-bit) or GS segment (64-bit), so this method sets a Register value for one these over
 * the program. 
 */
public class ThreadEnvironmentBlock {

	private Program program;
	private int winVersion;		// Ordered Windows version  3.10 => 30010, Win 20000 => 50000, XP => 50001, Vista => 60000
	private boolean is64Bit;
	private Address tebAddress;	// Where to map TEB in RAM
	private int blockSize;
	private DataType DWORDsize;
	private DataType DWORD;
	private DataType PVOID;
	private DataType ULONGLONG;
	private DataType ULONG;
	private DataType LONG;
	private DataType ULONG_PTR;
	private DataType USHORT;
	private DataType CHAR;
	private DataType UCHAR;
	private DataType WCHAR;
	private DataType BOOLEAN;
	private DataType HANDLE;
	private DataType GUID;
	private StructureDataType CLIENT_ID;

	public static final String BLOCK_NAME = "tdb";

	/**
	 * An enumeration describing a Windows OS version by String and by ordinal.
	 * The most significant 1 or 2 digits of the ordinal specify the major Windows release.
	 * The least significant 4 digits provide the minor release.
	 */
	public static enum WinVersion {
		WIN_3_10(30010, "Windows 3.10"),
		WIN_3_50(30050, "Windows 3.50"),
		WIN_95(40000, "Windows 95"),
		WIN_2000(50000, "Windows 2000"),
		WIN_XP(50001, "Windows XP"),
		WIN_VISTA(60000, "Windows Vista"),
		WIN_7(60001, "Windows 7"),
		WIN_10(100000, "Windows 10"),
		WIN_LATEST(101900, "Latest");

		private String display;
		private int order;

		WinVersion(int ord, String disp) {
			display = disp;
			order = ord;
		}

		public int getOrder() {
			return order;
		}

		@Override
		public String toString() {
			return display;
		}
	}

	/**
	 * Class for creating specific fields of the TEB data structure
	 */
	private static abstract class LayDown {
		protected boolean is64Bit;

		/**
		 * Create a single field given an offset, name, and data-type
		 * @param off32 is the offset for the 32-bit TEB (-1 means unused)
		 * @param off64 is the offset for the 64-bit TEB (-1 means unused)
		 * @param name is the name of the field
		 * @param dat is the data-type of the field
		 */
		public abstract void addEntry(int off32, int off64, String name, DataType dat);

		public LayDown(boolean is64) {
			is64Bit = is64;
		}
	}

	/**
	 * Create TEB fields as components of a Structure data-type
	 */
	private static class LayDownStructure extends LayDown {
		protected StructureDataType tebDataType;

		@Override
		public void addEntry(int off32, int off64, String name, DataType dat) {
			int offset = is64Bit ? off64 : off32;
			if (offset < 0) {
				return;
			}
			tebDataType.insertAtOffset(offset, dat, dat.getLength(), name, null);
		}

		public LayDownStructure(boolean is64) {
			super(is64);
			tebDataType = new StructureDataType("TEB", 0);
		}
	}

	/**
	 * Create TEB fields as Symbols and CodeUnits on a MemoryBlock
	 */
	private static class LayDownFlat extends LayDown {
		private Listing listing;
		private DataTypeManager dtManager;
		private SymbolTable symbolTable;
		private Address baseAddr;

		@Override
		public void addEntry(int off32, int off64, String name, DataType dat) {
			int offset = is64Bit ? off64 : off32;
			if (offset < 0) {
				return;
			}
			Address addr = baseAddr.add(offset);
			DataType clone = dat.clone(dtManager);
			try {
				listing.createData(addr, clone);
				symbolTable.createLabel(addr, name, SourceType.ANALYSIS);
			}
			catch (CodeUnitInsertionException e) {
				Msg.warn(this, "Unable to insert TEB field: " + name);
			}
			catch (InvalidInputException e) {
				Msg.warn(this, "Unable to create TEB symbol name: " + name);
			}
		}

		public LayDownFlat(Program program, Address addr, boolean is64) {
			super(is64);
			listing = program.getListing();
			dtManager = program.getDataTypeManager();
			symbolTable = program.getSymbolTable();
			baseAddr = addr;
		}
	}

	/**
	 * Set up (by name) the primitive data-types used by TEB fields.
	 */
	private void setupDataTypes() {
		DWORDsize = is64Bit ? QWordDataType.dataType : DWordDataType.dataType;
		DWORD = DWordDataType.dataType;		// Always size 4
		PVOID = VoidDataType.dataType;
		if (is64Bit) {
			PVOID = new Pointer64DataType(PVOID);
			ULONG_PTR = PVOID;
		}
		else {
			PVOID = new Pointer32DataType(PVOID);
			ULONG_PTR = PVOID;
		}
		ULONGLONG = UnsignedLongLongDataType.dataType;	// Always size 8
		ULONG = DWordDataType.dataType;		// Always size 4
		LONG = DWordDataType.dataType;
		USHORT = UnsignedShortDataType.dataType;
		UCHAR = UnsignedCharDataType.dataType;
		WCHAR = WideChar16DataType.dataType;
		CHAR = CharDataType.dataType;
		BOOLEAN = BooleanDataType.dataType;
		HANDLE = PVOID;
		GUID = new GuidDataType();
		CLIENT_ID = new StructureDataType("CLIENT_ID", 0);
		CLIENT_ID.add(HANDLE, HANDLE.getLength(), "UniqueProcess", null);
		CLIENT_ID.add(HANDLE, HANDLE.getLength(), "UniqueThread", null);
	}

	/**
	 * Create the TEB data structure by passing (offset, name, data-type) triples
	 * to the given field factory.  The exact fields created is determined by
	 * the winVersion variable, specifying the Windows OS version. 
	 * @param laydown is the given field factory
	 */
	private void create(LayDown laydown) {

		// TIB
		laydown.addEntry(0, 0, "ExceptionList", PVOID);
		laydown.addEntry(4, 8, "StackBase", PVOID);
		laydown.addEntry(8, 0x10, "StackLimit", PVOID);
		laydown.addEntry(0x0c, 0x18, "SubSystemTib", PVOID);
		laydown.addEntry(0x10, 0x20, "FiberData", PVOID);
		laydown.addEntry(0x14, 0x28, "ArbitraryUserPointer", PVOID);
		laydown.addEntry(0x18, 0x30, "Self", PVOID);

		laydown.addEntry(0x1c, 0x38, "EnvironmentPointer", PVOID);
		laydown.addEntry(0x20, 0x40, "ClientId", CLIENT_ID);
		if (winVersion <= 30010) {
			laydown.addEntry(0x28, 0x50, "pCSR_QLPC_TEB", PVOID);
			laydown.addEntry(0x38, 0x6c, "unkbyte", DWORD);
		}
		else {
			laydown.addEntry(0x28, 0x50, "ActiveRpcHandle", PVOID);
			laydown.addEntry(0x38, 0x6c, "CountOfOwnedCriticalSections", ULONG);
		}
		laydown.addEntry(0x2c, 0x58, "ThreadLocalStoragePointer", PVOID);
		laydown.addEntry(0x30, 0x60, "ProcessEnvironmentBlock", PVOID);
		laydown.addEntry(0x34, 0x68, "LastErrorValue", ULONG);

		if (winVersion <= 30051) {
			laydown.addEntry(0x3c, -1, "Win32ProcessInfo", PVOID);
		}
		else if (winVersion >= 40000) {
			laydown.addEntry(0x3c, 0x70, "CsrClientThread", PVOID);
		}
		if (winVersion >= 30050) {
			laydown.addEntry(0x40, 0x78, "Win32ThreadInfo", PVOID);		// THREADINFO data-type
		}
		if (winVersion <= 30051) {
			laydown.addEntry(0x44, -1, "CsrQlpcStack", PVOID);
		}
		if (winVersion == 40000) {
			DataType dt = new ArrayDataType(ULONG, 0x1f, ULONG.getLength());
			laydown.addEntry(0x44, -1, "Win32ClientInfo", dt);
		}
		else if (winVersion >= 50000) {
			DataType dt = new ArrayDataType(ULONG, 0x1a, ULONG.getLength());
			laydown.addEntry(0x44, 0x80, "User32Reserved", dt);
		}
		if (winVersion >= 50000) {
			DataType dt = new ArrayDataType(ULONG, 5, ULONG.getLength());
			laydown.addEntry(0xac, 0xe8, "UserReserved", dt);
		}
		if (winVersion >= 40000) {
			laydown.addEntry(0xc0, 0x100, "WOW32Reserved", PVOID);
		}
		laydown.addEntry(0xc4, 0x108, "CurrentLocale", ULONG);
		laydown.addEntry(0xc8, 0x10c, "FpSoftwareStatusRegister", ULONG);

		if (winVersion >= 100000) {
			DataType dt = new ArrayDataType(PVOID, 0x10, PVOID.getLength());
			laydown.addEntry(0xcc, 0x110, "ReservedForDebuggingInstrumentation", dt);
		}
		if (winVersion <= 60003) {
			DataType dt = new ArrayDataType(PVOID, 0x36, PVOID.getLength());
			laydown.addEntry(0xcc, 0x110, "SystemReserved1", dt);
		}
		else if (winVersion <= 101511) {
			DataType dt = new ArrayDataType(PVOID, 0x26, PVOID.getLength());
			laydown.addEntry(0x10c, 0x190, "SystemReserved1", dt);
		}
		else if (winVersion <= 101607) {
			DataType dt = new ArrayDataType(PVOID, 0x24, PVOID.getLength());
			laydown.addEntry(0x10c, 0x190, "SystemReserved1", dt);
		}
		else if (winVersion <= 101703) {
			DataType dt = new ArrayDataType(PVOID, 0x1e, PVOID.getLength());
			laydown.addEntry(0x10c, 0x190, "SystemReserved1", dt);
		}
		else {
			DataType dt = new ArrayDataType(PVOID, 0x1a, PVOID.getLength());
			laydown.addEntry(0x10c, 0x190, "SystemReserved1", dt);
		}
		if (winVersion >= 101709) {
			laydown.addEntry(0x174, 0x280, "PlaceholderCompatibilityMode", CHAR);
		}
		if (winVersion >= 101809) {
			laydown.addEntry(0x175, 0x281, "PlaceholderHydrationAlwaysExplicit", BOOLEAN);
		}
		if (winVersion >= 101709 && winVersion <= 101803) {
			DataType dt = new ArrayDataType(CHAR, 0x11, CHAR.getLength());
			laydown.addEntry(0x175, 0x281, "PlaceholderReserved", dt);
		}
		else if (winVersion >= 101809) {
			DataType dt = new ArrayDataType(CHAR, 0x10, CHAR.getLength());
			laydown.addEntry(0x176, 0x282, "PlaceholderReserved", dt);
		}
		if (winVersion >= 101709) {
			laydown.addEntry(0x180, 0x28c, "ProxiedProcessId", DWORD);
		}
		if (winVersion >= 101703) {
			laydown.addEntry(0x184, 0x290, "ActivationStack", DWORDsize);		// ACTIVATION_CONTEXT_STACK data-type
		}
		if (winVersion >= 101607) {
			DataType dt = new ArrayDataType(UCHAR, 8, UCHAR.getLength());
			laydown.addEntry(0x19c, 0x2b8, "WorkingOnBehalfOfTicket", dt);
		}
		if (winVersion >= 30010 && winVersion <= 40000) {
			laydown.addEntry(0x1a4, -1, "Spare1", PVOID);
		}
		if (winVersion >= 30010 && winVersion <= 30051) {
			laydown.addEntry(0x1a8, -1, "Spare2", PVOID);
		}
		if (winVersion == 40000) {
			laydown.addEntry(0x1a8, 0x2c0, "ExceptionCode", LONG);
		}
		else if (winVersion > 40000) {
			laydown.addEntry(0x1a4, 0x2c0, "ExceptionCode", LONG);
		}
		if (winVersion > 60003) {
			DataType dt = new ArrayDataType(UCHAR, 4, UCHAR.getLength());
			laydown.addEntry(-1, 0x2c4, "Padding0", dt);
		}
		if (winVersion == 30010) {
			laydown.addEntry(0x1ac, -1, "Win32ThreadInfo", PVOID);
			laydown.addEntry(0x1b0, -1, "Win32ProcessInfo", PVOID);
			DataType dt = new ArrayDataType(HANDLE, 2, HANDLE.getLength());
			laydown.addEntry(0x1dc, -1, "DbgSsReserved", dt);
		}
		else if (winVersion >= 30050 && winVersion <= 30051) {
			DataType dt = new ArrayDataType(PVOID, 5, PVOID.getLength());
			laydown.addEntry(0x1ac, -1, "CsrQlpcTeb", dt);
			laydown.addEntry(0x1c0, -1, "Win32ClientInfo", dt);
		}
		if (winVersion >= 50001 && winVersion <= 50002) {
			laydown.addEntry(0x1a8, -1, "ActivationContextStack", DWORDsize);	// ACTIVATION_CONTEXT_STACK data-type
		}
		else if (winVersion > 50002) {
			laydown.addEntry(0x1a8, -1, "ActivationContextStackPointer", PVOID);	// Pointer to ACTIVATION_CONTEXT_STACK
		}
		if (winVersion >= 100000) {
			laydown.addEntry(0x1ac, -1, "InstrumentationCallbackSp", ULONG_PTR);
			laydown.addEntry(0x1b0, -1, "InstrumentationCallbackPreviousPc", ULONG_PTR);
			laydown.addEntry(0x1b4, -1, "InstrumentationCallbackPreviousSp", ULONG_PTR);
			laydown.addEntry(0x1b8, -1, "InstrumentationCallbackDisabled", BOOLEAN);
		}
		if (winVersion == 40000) {
			DataType dt = new ArrayDataType(UCHAR, 0x28, UCHAR.getLength());
			laydown.addEntry(0x1ac, -1, "SpareBytes1", dt);
		}
		else if (winVersion == 50000) {
			DataType dt = new ArrayDataType(UCHAR, 0x2c, UCHAR.getLength());
			laydown.addEntry(0x1a8, -1, "SpareBytes1", dt);
		}
		else if (winVersion >= 50001 && winVersion <= 50002) {
			DataType dt = new ArrayDataType(UCHAR, 0x18, UCHAR.getLength());
			laydown.addEntry(0x1bc, -1, "SpareBytes1", dt);
		}
		else if (winVersion == 60000) {
			DataType dt = new ArrayDataType(UCHAR, 0x24, UCHAR.getLength());
			laydown.addEntry(0x1ac, -1, "SpareBytes1", dt);
		}
		else if (winVersion >= 60001 && winVersion <= 60003) {
			DataType dt = new ArrayDataType(UCHAR, 0x24, UCHAR.getLength());
			laydown.addEntry(0x1ac, -1, "SpareBytes", dt);
		}
		else if (winVersion >= 100000) {
			DataType dt = new ArrayDataType(UCHAR, 0x17, UCHAR.getLength());
			laydown.addEntry(0x1b9, -1, "SpareBytes", dt);
		}
		if (winVersion >= 60000) {
			laydown.addEntry(0x1d0, -1, "TxFsContext", ULONG);
		}
		if (winVersion > 50002) {
			laydown.addEntry(-1, 0x2c8, "ActivationContextStackPointer", PVOID);	// Pointer to ACTIVATION_CONTEXT_STACK
		}
		if (winVersion == 60000) {
			DataType dt = new ArrayDataType(UCHAR, 0x18, UCHAR.getLength());
			laydown.addEntry(-1, 0x2d0, "SpareBytes1", dt);
		}
		else if (winVersion >= 60001 && winVersion <= 60003) {
			DataType dt = new ArrayDataType(UCHAR, 0x18, UCHAR.getLength());
			laydown.addEntry(-1, 0x2d0, "SpareBytes", dt);
		}
		if (winVersion >= 100000) {
			laydown.addEntry(-1, 0x2d0, "InstrumentationCallbackSp", ULONG_PTR);
			laydown.addEntry(-1, 0x2d8, "InstrumentationCallbackPreviousPc", ULONG_PTR);
			laydown.addEntry(-1, 0x2e0, "InstrumentationCallbackPreviousSp", ULONG_PTR);
		}
		if (winVersion >= 60000) {
			laydown.addEntry(-1, 0x2e8, "TxFsContext", ULONG);
		}
		if (winVersion >= 100000) {
			laydown.addEntry(-1, 0x2ec, "InstrumentationCallbackDisabled", BOOLEAN);
		}
		if (winVersion >= 101809) {
			laydown.addEntry(-1, 0x2ed, "UnalignedLoadStoreExceptions", BOOLEAN);
		}
		if (winVersion == 60003) {
			DataType dt = new ArrayDataType(UCHAR, 4, UCHAR.getLength());
			laydown.addEntry(-1, 0x2ec, "Padding1", dt);
		}
		else if (winVersion >= 100000 && winVersion <= 101803) {
			DataType dt = new ArrayDataType(UCHAR, 3, UCHAR.getLength());
			laydown.addEntry(-1, 0x2ed, "Padding1", dt);
		}
		else {
			DataType dt = new ArrayDataType(UCHAR, 2, UCHAR.getLength());
			laydown.addEntry(-1, 0x2ee, "Padding1", dt);
		}
		if (winVersion == 30010) {
			DataType dt = new ArrayDataType(PVOID, 0x143, PVOID.getLength());
			laydown.addEntry(0x1e4, -1, "SystemReserved2", dt);
		}
		else if (winVersion >= 30050 && winVersion <= 30051) {
			DataType dt = new ArrayDataType(PVOID, 0x142, PVOID.getLength());
			laydown.addEntry(0x1d4, -1, "SystemReserved2", dt);
		}
		else if (winVersion == 40000) {
			DataType dt = new ArrayDataType(PVOID, 0xa, PVOID.getLength());
			laydown.addEntry(0x1d4, -1, "SystemReserved2", dt);
		}
		if (winVersion == 40000) {
			laydown.addEntry(0x1fc, 0x2f0, "GdiTebBatch", DWORDsize);	// GDI_TEB_BATCH data-type
		}
		else if (winVersion > 40000) {
			laydown.addEntry(0x1d4, 0x2f0, "GdiTebBatch", DWORDsize);	// GDI_TEB_BATCH data-type
		}
		if (winVersion >= 30050 && winVersion <= 40000) {
			laydown.addEntry(0x6dc, -1, "gdiRgn", ULONG);
			laydown.addEntry(0x6e0, -1, "gdiPen", ULONG);
			laydown.addEntry(0x6e4, -1, "gdiBrush", ULONG);
		}
		if (winVersion >= 30050 && winVersion <= 40000) {
			laydown.addEntry(0x6e8, 0x7d8, "RealClientId", CLIENT_ID);
		}
		else if (winVersion > 40000) {
			laydown.addEntry(0x6b4, 0x7d8, "RealClientId", CLIENT_ID);
		}
		if (winVersion >= 30010 && winVersion < 30050) {
			laydown.addEntry(0x6f0, 0x7e8, "CsrQlpcStack", PVOID);
		}
		else if (winVersion >= 30050 && winVersion <= 40000) {
			laydown.addEntry(0x6f0, 0x7e8, "GdiCachedProcessHandle", PVOID);
		}
		else if (winVersion > 40000) {
			laydown.addEntry(0x6bc, 0x7e8, "GdiCachedProcessHandle", PVOID);
		}
		if (winVersion >= 30010 && winVersion <= 40000) {
			laydown.addEntry(0x6f4, 0x7f0, "GdiClientPID", ULONG);
			laydown.addEntry(0x6f8, 0x7f4, "GdiCLientTID", ULONG);
			laydown.addEntry(0x6fc, 0x7f8, "GdiThreadLocalInfo", PVOID);
		}
		else if (winVersion > 40000) {
			laydown.addEntry(0x6c0, 0x7f0, "GdiClientPID", ULONG);
			laydown.addEntry(0x6c4, 0x7f4, "GdiCLientTID", ULONG);
			laydown.addEntry(0x6c8, 0x7f8, "GdiThreadLocalInfo", PVOID);
		}
		if (winVersion >= 30010 && winVersion <= 30051) {
			laydown.addEntry(0x700, -1, "User32Reserved0", PVOID);
			laydown.addEntry(0x704, -1, "User32Reserved1", PVOID);
		}
		if (winVersion == 30010) {
			DataType dt = new ArrayDataType(PVOID, 0x13b, PVOID.getLength());
			laydown.addEntry(0x708, 0x800, "UserReserved", dt);
		}
		else if (winVersion == 30051) {
			DataType dt = new ArrayDataType(PVOID, 3, PVOID.getLength());
			laydown.addEntry(0x708, 0x800, "UserReserved", dt);
		}
		else if (winVersion == 40000) {
			DataType dt = new ArrayDataType(PVOID, 5, PVOID.getLength());
			laydown.addEntry(0x700, 0x800, "UserReserved", dt);
		}
		else if (winVersion >= 50000) {
			DataType dt = new ArrayDataType(ULONG_PTR, 0x3e, ULONG_PTR.getLength());
			laydown.addEntry(0x6cc, 0x800, "Win32ClientInfo", dt);
		}
		if (winVersion == 30051) {
			DataType dt = new ArrayDataType(PVOID, 0x133, PVOID.getLength());
			laydown.addEntry(0x714, 0x9f0, "glDispatchTable", dt);
		}
		else if (winVersion == 40000) {
			DataType dt = new ArrayDataType(PVOID, 0x118, PVOID.getLength());
			laydown.addEntry(0x714, 0x9f0, "glDispatchTable", dt);
		}
		else if (winVersion > 40000) {
			DataType dt = new ArrayDataType(PVOID, 0xe9, PVOID.getLength());
			laydown.addEntry(0x7c4, 0x9f0, "glDispatchTable", dt);
		}
		if (winVersion == 40000) {
			DataType dt = new ArrayDataType(ULONG_PTR, 0x1a, ULONG_PTR.getLength());
			laydown.addEntry(0xb74, 0x1138, "glReserved1", dt);
		}
		else if (winVersion >= 50000) {
			DataType dt = new ArrayDataType(ULONG_PTR, 0x1d, ULONG_PTR.getLength());
			laydown.addEntry(0xb68, 0x1138, "glReserved1", dt);
		}
		if (winVersion >= 40000) {
			laydown.addEntry(0xbdc, 0x1220, "glReserved2", PVOID);
		}
		if (winVersion >= 30050) {
			laydown.addEntry(0xbe0, 0x1228, "glSectionInfo", PVOID);
			laydown.addEntry(0xbe4, 0x1230, "glSection", PVOID);
			laydown.addEntry(0xbe8, 0x1238, "glTable", PVOID);
			laydown.addEntry(0xbec, 0x1240, "glCurrentRC", PVOID);
			laydown.addEntry(0xbf0, 0x1248, "glContext", PVOID);
		}
		laydown.addEntry(0xbf4, 0x1250, "LastStatusValue", ULONG);
		if (winVersion >= 60003) {
			DataType dt = new ArrayDataType(UCHAR, 4, UCHAR.getLength());
			laydown.addEntry(-1, 0x1254, "Padding2", dt);
		}
// TODO:		laydown.addEntry(0xbf8, 0x1258, "StaticUnicodeString", UNICODE_STRING);
		DataType bufdt = new ArrayDataType(WCHAR, 0x105, WCHAR.getLength());
		laydown.addEntry(0xc00, 0x1268, "StaticUnicodeBuffer", bufdt);
		if (winVersion >= 60003) {
			DataType dt = new ArrayDataType(UCHAR, 6, UCHAR.getLength());
			laydown.addEntry(-1, 0x1472, "Padding3", dt);
		}
		laydown.addEntry(0xe0c, 0x1478, "DeallocationStack", PVOID);
		DataType ptrdt = new ArrayDataType(PVOID, 0x40, PVOID.getLength());
		laydown.addEntry(0xe10, 0x1480, "TlsSlots", ptrdt);
// TODO:		laydown.addEntry(0xf10, 0x1680, "TlsLinks", LIST_ENTRY);
		laydown.addEntry(0xf10, 0x1680, "TlsLinks.Flink", PVOID);
		laydown.addEntry(0xf14, 0x1688, "TlsLinks.Blink", PVOID);
		laydown.addEntry(0xf18, 0x1690, "Vdm", PVOID);
		laydown.addEntry(0xf1c, 0x1698, "ReservedForNtRpc", PVOID);
		DataType handledt = new ArrayDataType(HANDLE, 2, HANDLE.getLength());
		laydown.addEntry(0xf20, 0x16a0, "DbgSsReserved", handledt);
		if (winVersion >= 40000 && winVersion <= 50001) {
			laydown.addEntry(0xf28, 0x16b0, "HardErrorsAreDisabled", ULONG);
		}
		else if (winVersion >= 50002) {
			laydown.addEntry(0xf28, 0x16b0, "HardErrorMode", ULONG);
		}
		if (winVersion >= 60003) {
			DataType dt = new ArrayDataType(UCHAR, 4, UCHAR.getLength());
			laydown.addEntry(-1, 0x16b4, "Padding4", dt);
		}
		if (winVersion >= 40000 && winVersion <= 50002) {
			DataType dt = new ArrayDataType(PVOID, 0x10, PVOID.getLength());
			laydown.addEntry(0xf2c, 0x16b8, "Instrumentation", dt);
		}
		else if (winVersion >= 60000) {
			DataType dt = new ArrayDataType(PVOID, is64Bit ? 0xb : 0x9, PVOID.getLength());
			laydown.addEntry(0xf2c, 0x16b8, "Instrumentation", dt);
		}
		if (winVersion >= 60000) {
			laydown.addEntry(0xf50, 0x1710, "ActivityId", GUID);
		}
		if (winVersion > 50002) {
			laydown.addEntry(0xf60, 0x1720, "SubProcessTag", PVOID);
		}
		if (winVersion >= 60000 && winVersion <= 60001) {
			laydown.addEntry(0xf64, 0x1728, "EtwLocalData", PVOID);
		}
		else if (winVersion >= 60002) {
			laydown.addEntry(0xf64, 0x1728, "PerflibData", PVOID);
		}
		if (winVersion > 50002) {
			laydown.addEntry(0xf68, 0x1730, "EtwTraceData", PVOID);
		}
		if (winVersion >= 40000) {
			laydown.addEntry(0xf6c, 0x1738, "WinSockData", PVOID);
			laydown.addEntry(0xf70, 0x1740, "GdiBatchCount", ULONG);
		}
		if (winVersion >= 60001) {
			laydown.addEntry(0xf74, 0x1744, "IdealProcessorValue", ULONG);
		}
		if (winVersion > 50002) {
			laydown.addEntry(0xf78, 0x748, "GuaranteedStackBytes", ULONG);
		}
		if (winVersion >= 50000) {
			laydown.addEntry(0xf7c, 0x1750, "ReservedForPerf", PVOID);
		}
		if (winVersion >= 40000) {
			laydown.addEntry(0xf80, 0x1758, "ReservedForOle", PVOID);
			laydown.addEntry(0xf84, 0x1760, "WaitingOnLoaderLock", ULONG);
		}
		if (winVersion >= 60000) {
			laydown.addEntry(0xf88, 0x1768, "SavedPriorityState", PVOID);
		}
		if (winVersion >= 50002 && winVersion <= 60001) {
			laydown.addEntry(0xf8c, 0x1770, "SoftPatchPtr1", ULONG_PTR);
		}
		else if (winVersion >= 60002) {
			laydown.addEntry(0xf8c, 0x1770, "ReservedForCodeCoverage", ULONG_PTR);
		}
		if (winVersion >= 60000) {
			laydown.addEntry(0xf90, 0x1778, "ThreadPoolData", PVOID);
		}
		if (winVersion >= 50000) {
			laydown.addEntry(0xf94, 0x1780, "TlsExpansionSlots", PVOID);
		}
		if (winVersion > 50002) {
			laydown.addEntry(-1, 0x1788, "DeallocationBStore", PVOID);
			laydown.addEntry(-1, 0x1790, "BStoreLimit", PVOID);
		}
		if (winVersion >= 50000 && winVersion <= 60000) {
			laydown.addEntry(0xf98, 0x1798, "ImpersonationLocale", ULONG);
		}
		else if (winVersion >= 60001) {
			laydown.addEntry(0xf98, 0x1798, "MuiGeneration", ULONG);
		}
		if (winVersion >= 50000) {
			laydown.addEntry(0xf9c, 0x179c, "IsImpersonating", ULONG);
			laydown.addEntry(0xfa0, 0x17a0, "NlsCache", PVOID);
		}
		if (winVersion >= 50001) {
			laydown.addEntry(0xfa4, 0x17a8, "pShimData", PVOID);
		}
		if (winVersion >= 50001 && winVersion <= 60001) {
			laydown.addEntry(0xfa8, 0x17b0, "HeapVirtualAffinity", ULONG);
		}
		else if (winVersion >= 60002 && winVersion <= 101803) {
			laydown.addEntry(0xfa8, 0x17b0, "HeapVirtualAffinity", USHORT);
		}
		else if (winVersion >= 101809) {
			laydown.addEntry(0xfa8, 0x17b0, "HeapData", ULONG);
		}
		if (winVersion >= 60002 && winVersion <= 101803) {
			laydown.addEntry(0xfaa, 0x17b2, "LowFragHeapDataSlot", USHORT);
		}
		if (winVersion >= 50001) {
			laydown.addEntry(0xfac, 0x17b8, "CurrentTransactionHandle", PVOID);
			laydown.addEntry(0xfb0, 0x17c0, "ActiveFrame", PVOID);	// Pointer to TEB_ACTIVE_FRAME
		}
		if (winVersion >= 50002) {
			laydown.addEntry(0xfb4, 0x17c8, "FlsData", PVOID);
		}
		if (winVersion >= 60000) {
			laydown.addEntry(0xfb8, 0x17d0, "PreferredLanguages", PVOID);
			laydown.addEntry(0xfbc, 0x17d8, "UserPrefLanguages", PVOID);
			laydown.addEntry(0xfc0, 0x17e0, "MergedPrefLanguages", PVOID);
			laydown.addEntry(0xfc4, 0x17e8, "MuiImpersonation", ULONG);
			laydown.addEntry(0xfc8, 0x17ec, "CrossTebFlags", USHORT);
			laydown.addEntry(0xfca, 0x17ee, "SameTebFlags", USHORT);
			laydown.addEntry(0xfcc, 0x17f0, "TxnScopeEnterCallback", PVOID);
			laydown.addEntry(0xfd0, 0x17f8, "TxnScopeExitCallback", PVOID);
			laydown.addEntry(0xfd4, 0x1800, "TxnScopeContext", PVOID);
			laydown.addEntry(0xfd8, 0x1808, "LockCount", ULONG);
		}
		if (winVersion >= 100000) {
			laydown.addEntry(0xfdc, 0x180c, "WowTebOffset", LONG);
		}
		if (winVersion >= 60001) {
			laydown.addEntry(0xfe0, 0x1810, "ResourceRetValue", PVOID);
		}
		if (winVersion >= 60002) {
			laydown.addEntry(0xfe4, 0x1818, "ReservedForWdf", PVOID);
		}
		if (winVersion >= 100000) {
			laydown.addEntry(0xfe8, 0x1820, "ReservedForCrt", ULONGLONG);
			laydown.addEntry(0xff0, 0x1828, "EffectiveContainerId", GUID);
		}
	}

	/**
	 * Clear any Symbols or CodeUnits on the given block
	 * @param block is the specific MemoryBlock to clear
	 */
	private void clearBlock(MemoryBlock block) {
		Listing listing = program.getListing();
		Address endAddr = tebAddress.add(blockSize - 1);
		listing.clearCodeUnits(tebAddress, endAddr, false);
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator iter = symbolTable.getSymbolIterator(tebAddress, true);
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			if (!block.contains(sym.getAddress())) {
				break;
			}
			sym.delete();
		}
	}

	/**
	 * Create TEB as a single uninitialized block.  A TEB structure is created and is
	 * placed on the block.
	 * @throws MemoryConflictException if there are overlap problems with other blocks 
	 * @throws AddressOverflowException for problems with block's start Address
	 * @throws IllegalArgumentException for problems with the block name or the TEB data-type
	 * @throws LockException if it cannot get an exclusive lock on the program
	 * @throws CodeUnitInsertionException for problems laying down the structure on the block
	 * @throws InvalidInputException for problems with the symbol name attached to the TEB
	 */
	public void createBlockAndStructure() throws MemoryConflictException, LockException,
			IllegalArgumentException, AddressOverflowException, CodeUnitInsertionException,
			InvalidInputException {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(BLOCK_NAME);
		if (block != null) {
			if (!block.getStart().equals(tebAddress) || block.getSize() != blockSize ||
				block.isInitialized()) {
				throw new MemoryConflictException("Incompatible " + BLOCK_NAME + " block exists");
			}
			clearBlock(block);
		}
		else {
			block = memory.createUninitializedBlock(BLOCK_NAME, tebAddress, blockSize, false);
		}
		block.setWrite(true);
		LayDownStructure laydown = new LayDownStructure(is64Bit);
		create(laydown);
		if (is64Bit) {
			DataType selfRef = new Pointer64DataType(laydown.tebDataType);
			laydown.tebDataType.replaceAtOffset(0x30, selfRef, 8, "Self", null);
		}
		else {
			DataType selfRef = new Pointer32DataType(laydown.tebDataType);
			laydown.tebDataType.replaceAtOffset(0x18, selfRef, 4, "Self", null);
		}
		Listing listing = program.getListing();
		listing.createData(tebAddress, laydown.tebDataType);
		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(tebAddress, "TEB", SourceType.ANALYSIS);
	}

	/**
	 * Get the bytes for the TEB.  These are all initialized to zero except for
	 * the "Self" field, which is set so that it contains the starting address
	 * of the TEB, allowing the ConstantPropagator to pick it up.
	 * @return the bytes as an InputStream
	 */
	private ByteArrayInputStream getTEBBytes() {
		byte buffer[] = new byte[blockSize];
		for (int i = 0; i < blockSize; ++i) {
			buffer[i] = 0;
		}
		long offset = tebAddress.getOffset();
		if (is64Bit) {
			for (int i = 0; i < 8; ++i) {
				buffer[0x30 + i] = (byte) offset;
				offset >>= 8;
			}
		}
		else {
			for (int i = 0; i < 4; ++i) {
				buffer[0x18 + i] = (byte) offset;
				offset >>= 8;
			}
		}
		return new ByteArrayInputStream(buffer);
	}

	/**
	 * Mark a specific Data element as read-only
	 * @param data is the given Data element
	 */
	private void markDataAsConstant(Data data) {
		SettingsDefinition[] settings = data.getDataType().getSettingsDefinitions();
		for (SettingsDefinition definitions : settings) {
			if (definitions instanceof MutabilitySettingsDefinition) {
				MutabilitySettingsDefinition setting = (MutabilitySettingsDefinition) definitions;
				setting.setChoice(data, MutabilitySettingsDefinition.CONSTANT);
			}
		}
	}

	/**
	 * Create 2 blocks, one that is initialized to hold a proper value for the TEB Self reference field
	 * and another to hold the remainder of the TEB.  The data structure is layed down as a
	 * series of symbols on these blocks.
	 * @throws MemoryConflictException if there are overlap problems with other blocks 
	 * @throws CancelledException if block creation is cancelled
	 * @throws AddressOverflowException for problems with block's start Address
	 * @throws IllegalArgumentException for problems with the block name or the TEB data-type
	 * @throws LockException if it cannot get an exclusive lock on the program
	 */
	public void createBlocksAndSymbols() throws MemoryConflictException, LockException,
			IllegalArgumentException, AddressOverflowException, CancelledException {
		Memory memory = program.getMemory();
		MemoryBlock block1 = memory.getBlock(BLOCK_NAME);
		if (block1 != null) {
			if (!block1.getStart().equals(tebAddress) || block1.getSize() != blockSize ||
				!block1.isInitialized()) {
				throw new MemoryConflictException("Incompatible " + BLOCK_NAME + " block exists");
			}
			clearBlock(block1);
		}
		else {
			ByteArrayInputStream byteStream = getTEBBytes();
			block1 = memory.createInitializedBlock(BLOCK_NAME, tebAddress, byteStream, blockSize,
				null, false);
		}
		block1.setWrite(true);
		LayDownFlat laydown = new LayDownFlat(program, tebAddress, is64Bit);
		create(laydown);
		Data data = program.getListing().getDataAt(tebAddress.add(is64Bit ? 0x30 : 0x18));
		markDataAsConstant(data);
	}

	/**
	 * Set FS_OFFSET for 32-bit or GS_OFFSET for 64-bit to the address of the TEB across the program.
	 */
	public void setRegisterValue() {
		Register reg = program.getRegister(is64Bit ? "GS_OFFSET" : "FS_OFFSET");
		BigInteger val = BigInteger.valueOf(tebAddress.getOffset());
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isExecute()) {
				continue;
			}
			SetRegisterCmd cmd = new SetRegisterCmd(reg, block.getStart(), block.getEnd(), val);
			cmd.applyTo(program);
		}
	}

	/**
	 * @return true if a 64-bit TEB is being layed down.
	 */
	public boolean is64() {
		return is64Bit;
	}

	/**
	 * @return the number of bytes needed in the full TEB block being constructed
	 */
	public int getBlockSize() {
		return blockSize;
	}

	/**
	 * Set the starting address of the TEB
	 * @param addr is the Address to set
	 */
	public void setAddress(Address addr) {
		tebAddress = addr;
	}

	public ThreadEnvironmentBlock(Program prog, WinVersion version) {
		program = prog;
		tebAddress = null;
		winVersion = version.getOrder();
		is64Bit = program.getLanguageID().getIdAsString().contains("64");
		blockSize = is64Bit ? 0x1850 : 0x1000;
		setupDataTypes();
	}
}
