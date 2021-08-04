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
package ghidra.app.util.bin.format.pe;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.util.bin.format.pe.LoadConfigDirectory.GuardFlags;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * ControlFlowGuard is a platform security feature that was created to combat memory
 * corruption vulnerabilities.
 * <p>
 * ReturnFlowGuard was introduced as an addition to ControlFlowGuard in the Windows 10
 * Creator's update. 
 */
public class ControlFlowGuard {
	public static String GuardCFFunctionTableName = "GuardCFFunctionTable";
	public static String GuardCFAddressTakenIatTableName = "GuardCFAddressTakenIatTable";
	public static String GuardCfgTableEntryName = "GuardCfgTableEntry";

	/**
	 * Perform markup on the supported ControlFlowGuard and ReturnFlowGuard functions and 
	 * tables, if they exist.
	 * 
	 * @param lcd The PE LoadConfigDirectory.
	 * @param program The program.
	 * @param log The log.
	 * @param ntHeader The PE NTHeader.
	 */
	public static void markup(LoadConfigDirectory lcd, Program program, MessageLog log,
			NTHeader ntHeader) {

		boolean is64bit = ntHeader.getOptionalHeader().is64bit();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Memory mem = program.getMemory();
		SymbolTable symbolTable = program.getSymbolTable();

		// ControlFlowGuard
		markupCfgCheckFunction(lcd, program, is64bit, space, mem, symbolTable);
		markupCfgDispatchFunction(lcd, program, is64bit, space, mem, symbolTable);
		markupCfgFunctionTable(lcd, program, log);
		markupCfgAddressTakenIatEntryTable(lcd, program, log);

		// ReturnFlowGuard
		markupRfgFailureRoutine(lcd, program, space, symbolTable);
		markupRfgDefaultFailureRoutine(lcd, program, is64bit, space, mem, symbolTable);
		markupRfgDefaultStackPointerFunction(lcd, program, is64bit, space, mem, symbolTable);
	}

	/**
	 * Performs markup on the ControlFlowGuard check function, if it exists.
	 * 
	 * @param lcd The PE LoadConfigDirectory.
	 * @param program The program.
	 * @param is64bit True if the PE is 64-bit; false if it's 32-bit.
	 * @param space The program's address space.
	 * @param mem The program's memory.
	 * @param symbolTable The program's symbol table.
	 */
	private static void markupCfgCheckFunction(LoadConfigDirectory lcd, Program program,
			boolean is64bit, AddressSpace space, Memory mem, SymbolTable symbolTable) {

		if (lcd.getCfgCheckFunctionPointer() == 0) {
			return;
		}

		try {
			Address functionPointerAddr = space.getAddress(lcd.getCfgCheckFunctionPointer());
			Address functionAddr = space.getAddress(
				is64bit ? mem.getLong(functionPointerAddr) : mem.getInt(functionPointerAddr));
			symbolTable.createLabel(functionAddr, "_guard_check_icall", SourceType.IMPORTED);

			AbstractProgramLoader.markAsFunction(program, null, functionAddr);
		}
		catch (MemoryAccessException | AddressOutOfBoundsException | InvalidInputException e) {
			Msg.warn(ControlFlowGuard.class, "Unable to label ControlFlowGuard check function.", e);
		}
	}

	/**
	 * Performs markup on the ControlFlowGuard dispatch function, if it exists.
	 * 
	 * @param lcd The PE LoadConfigDirectory.
	 * @param program The program.
	 * @param is64bit True if the PE is 64-bit; false if it's 32-bit.
	 * @param space The program's address space.
	 * @param mem The program's memory.
	 * @param symbolTable The program's symbol table.
	 */
	private static void markupCfgDispatchFunction(LoadConfigDirectory lcd, Program program,
			boolean is64bit, AddressSpace space, Memory mem, SymbolTable symbolTable) {

		if (lcd.getCfgDispatchFunctionPointer() == 0) {
			return;
		}

		try {
			Address functionPointerAddr = space.getAddress(lcd.getCfgDispatchFunctionPointer());
			Address functionAddr = space.getAddress(
				is64bit ? mem.getLong(functionPointerAddr) : mem.getInt(functionPointerAddr));
			symbolTable.createLabel(functionAddr, "_guard_dispatch_icall", SourceType.IMPORTED);

			AbstractProgramLoader.markAsFunction(program, null, functionAddr);
		}
		catch (MemoryAccessException | AddressOutOfBoundsException | InvalidInputException e) {
			Msg.warn(ControlFlowGuard.class, "Unable to label ControlFlowGuard dispatch function.",
				e);
		}
	}

	/**
	 * Performs markup on the ControlFlowGuard function table, if it exists.
	 * 
	 * @param lcd The PE LoadConfigDirectory.
	 * @param program The program.
	 * @param log The log.
	 */
	private static void markupCfgFunctionTable(LoadConfigDirectory lcd, Program program,
			MessageLog log) {

		final int IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xf0000000;
		final int IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28;

		long tablePointer = lcd.getCfgFunctionTablePointer();
		long functionCount = lcd.getCfgFunctionCount();

		if (tablePointer == 0 || functionCount <= 0) {
			return;
		}

		Address tableAddr =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(tablePointer);

		// Label the start of the table
		try {
			program.getSymbolTable()
					.createLabel(tableAddr, GuardCFFunctionTableName, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			Msg.warn(ControlFlowGuard.class, "Unable to label ControlFlowGuard function table.", e);
		}

		// Each table entry is an RVA (32-bit image base offset), followed by 'n' extra bytes
		GuardFlags guardFlags = lcd.getCfgGuardFlags();
		int n = (guardFlags.getFlags() &
			IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;

		// Pre-define base data types used to define table entry data type
		DataType ibo32 = new ImageBaseOffset32DataType();
		DataType byteType = ByteDataType.dataType;

		CategoryPath categoryPath = new CategoryPath(CategoryPath.ROOT, "CFG");
		StructureDataType GuardCfgTableEntryType = (StructureDataType) program.getDataTypeManager()
				.getDataType(categoryPath, GuardCfgTableEntryName);

		if (GuardCfgTableEntryType == null) {
			GuardCfgTableEntryType = new StructureDataType(categoryPath, GuardCfgTableEntryName, 0);
			GuardCfgTableEntryType.setPackingEnabled(false);
			GuardCfgTableEntryType.add(ibo32, "Offset", "");
			if (n > 0) {
				ArrayDataType padType =
					new ArrayDataType(byteType, n / byteType.getLength(), byteType.getLength());
				GuardCfgTableEntryType.add(padType, "Pad", "");
			}
		}

		CreateArrayCmd cmd = new CreateArrayCmd(tableAddr, (int) functionCount,
			GuardCfgTableEntryType, GuardCfgTableEntryType.getLength());
		cmd.applyTo(program);

		Data tableData = program.getListing().getDataAt(tableAddr);
		createCfgFunctions(program, tableData, log);
	}

	private static void createCfgFunctions(Program program, Data tableData, MessageLog log) {
		if (tableData == null) {
			Msg.warn(ControlFlowGuard.class, "Couldn't find Control Flow Guard tables.");
			return;
		}

		if (!tableData.isArray() || (tableData.getNumComponents() < 1)) {
			Msg.warn(ControlFlowGuard.class, "Control Flow Guard table seems to be empty.");
			return;
		}

		for (Address target : getFunctionAddressesFromTable(program, tableData)) {
			AbstractProgramLoader.markAsFunction(program, null, target);
		}
	}

	private static List<Address> getFunctionAddressesFromTable(Program program, Data table) {
		List<Address> list = new ArrayList<Address>();

		// use the array and ibo data in structure to get a list of functions
		for (int i = 0; i < table.getNumComponents(); i++) {
			Data entry = table.getComponent(i);
			Data iboData = entry.getComponent(0);
			Object value = iboData.getValue();
			if (value instanceof Address) {
				list.add((Address) value);
			}
		}
		return list;
	}

	/**
	 * Performs markup on the ControlFlowGuard address taken IAT table, if it exists.
	 * 
	 * @param lcd The PE LoadConfigDirectory.
	 * @param program The program.
	 * @param log The log.
	 */
	private static void markupCfgAddressTakenIatEntryTable(LoadConfigDirectory lcd, Program program,
			MessageLog log) {

		long tablePointer = lcd.getGuardAddressIatTableTablePointer();
		long functionCount = lcd.getGuardAddressIatTableCount();

		if (tablePointer == 0 || functionCount <= 0) {
			return;
		}

		try {
			Address tableAddr =
				program.getAddressFactory().getDefaultAddressSpace().getAddress(tablePointer);

			// Label the start of the table
			program.getSymbolTable()
					.createLabel(tableAddr, GuardCFAddressTakenIatTableName, SourceType.IMPORTED);
			// Each table entry is an RVA (32-bit image base offset)
			DataType ibo32 = new ImageBaseOffset32DataType();
			for (long i = 0; i < functionCount; i++) {
				Data d =
					PeUtils.createData(program, tableAddr.add(i * ibo32.getLength()), ibo32, log);
				if (d == null) {
					// If we failed to create data on a table entry, just assume the rest will fail
					break;
				}
			}
		}
		catch (AddressOutOfBoundsException | InvalidInputException e) {
			Msg.warn(ControlFlowGuard.class, "Unable to label ControlFlowGuard IAT table.", e);
		}
	}

	/**
	 * Performs markup on the ReturnFlowGuard failure routine, if it exists.
	 * 
	 * @param lcd The PE LoadConfigDirectory.
	 * @param program The program
	 * @param space The program's address space.
	 * @param symbolTable The program's symbol table.
	 */
	private static void markupRfgFailureRoutine(LoadConfigDirectory lcd, Program program,
			AddressSpace space, SymbolTable symbolTable) {

		if (lcd.getRfgFailureRoutine() == 0) {
			return;
		}

		try {
			Address routineAddr = space.getAddress(lcd.getRfgFailureRoutine());
			symbolTable.createLabel(routineAddr, "_guard_ss_verify_failure", SourceType.IMPORTED);

			AbstractProgramLoader.markAsFunction(program, null, routineAddr);
		}
		catch (AddressOutOfBoundsException | InvalidInputException e) {
			Msg.warn(ControlFlowGuard.class, "Unable to label ReturnFlowGuard failure routine.", e);
		}
	}

	/**
	 * Performs markup on the ReturnFlowGuard "default" failure routine function, if it exists.
	 * 
	 * @param lcd The PE LoadConfigDirectory.
	 * @param program The program
	 * @param is64bit True if the PE is 64-bit; false if it's 32-bit.
	 * @param space The program's address space.
	 * @param mem The program's memory.
	 * @param symbolTable The program's symbol table.
	 */
	private static void markupRfgDefaultFailureRoutine(LoadConfigDirectory lcd, Program program,
			boolean is64bit, AddressSpace space, Memory mem, SymbolTable symbolTable) {

		if (lcd.getRfgFailureRoutineFunctionPointer() == 0) {
			return;
		}

		try {
			Address functionPointerAddr =
				space.getAddress(lcd.getRfgFailureRoutineFunctionPointer());
			Address functionAddr = space.getAddress(
				is64bit ? mem.getLong(functionPointerAddr) : mem.getInt(functionPointerAddr));
			symbolTable.createLabel(functionAddr, "_guard_ss_verify_failure_default",
				SourceType.IMPORTED);

			AbstractProgramLoader.markAsFunction(program, null, functionAddr);

		}
		catch (MemoryAccessException | AddressOutOfBoundsException | InvalidInputException e) {
			Msg.warn(ControlFlowGuard.class,
				"Unable to label ReturnFlowGuard default failure routine.", e);
		}
	}

	/**
	 * Performs markup on the ReturnFlowGuard verify stack pointer function, if it exists.
	 * 
	 * @param lcd The PE LoadConfigDirectory.
	 * @param program The program
	 * @param is64bit True if the PE is 64-bit; false if it's 32-bit.
	 * @param space The program's address space.
	 * @param mem The program's memory.
	 * @param symbolTable The program's symbol table.
	 */
	private static void markupRfgDefaultStackPointerFunction(LoadConfigDirectory lcd,
			Program program, boolean is64bit, AddressSpace space, Memory mem,
			SymbolTable symbolTable) {

		if (lcd.getRfgVerifyStackPointerFunctionPointer() == 0) {
			return;
		}

		try {
			Address functionPointerAddr =
				space.getAddress(lcd.getRfgVerifyStackPointerFunctionPointer());
			Address functionAddr = space.getAddress(
				is64bit ? mem.getLong(functionPointerAddr) : mem.getInt(functionPointerAddr));
			symbolTable.createLabel(functionAddr, "_guard_ss_verify_sp_default",
				SourceType.IMPORTED);

			AbstractProgramLoader.markAsFunction(program, null, functionAddr);

		}
		catch (MemoryAccessException | AddressOutOfBoundsException | InvalidInputException e) {
			Msg.warn(ControlFlowGuard.class,
				"Unable to label ReturnFlowGuard verify stack pointer function.", e);
		}
	}
}
