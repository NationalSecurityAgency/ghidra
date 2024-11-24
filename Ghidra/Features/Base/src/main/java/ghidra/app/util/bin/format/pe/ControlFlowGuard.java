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
import java.util.function.Supplier;

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

		// ControlFlowGuard
		markupCfgFunction("_guard_check_icall", "ControlFlowGuard check",
			lcd::getCfgCheckFunctionPointer, program, ntHeader, log);
		markupCfgFunction("_guard_dispatch_icall", "ControlFlowGuard dispatch",
			lcd::getCfgDispatchFunctionPointer, program, ntHeader, log);
		markupCfgFunctionTable(lcd, program, log);
		markupCfgAddressTakenIatEntryTable(lcd, program, log);

		// ReturnFlowGuard
		markupCfgFunction("_guard_ss_verify_failure", "ReturnFlowGuard failure",
			lcd::getRfgFailureRoutine, program, ntHeader, log);
		markupCfgFunction("_guard_ss_verify_failure_default", "ReturnFlowGuard default failure",
			lcd::getRfgFailureRoutineFunctionPointer, program, ntHeader, log);
		markupCfgFunction("_guard_ss_verify_sp_default", "ReturnFlowGuard verify stack pointer",
			lcd::getRfgVerifyStackPointerFunctionPointer, program, ntHeader, log);
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
			log.appendMsg("Unable to label ControlFlowGuard function table: " + e.getMessage());
		}

		// Each table entry is an RVA (32-bit image base offset), followed by 'n' extra bytes
		GuardFlags guardFlags = lcd.getCfgGuardFlags();
		int n = (guardFlags.getFlags() &
			IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;

		// Pre-define base data types used to define table entry data type
		DataType ibo32 = new IBO32DataType();
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
			log.appendMsg("Couldn't find Control Flow Guard tables.");
			return;
		}

		if (!tableData.isArray() || (tableData.getNumComponents() < 1)) {
			log.appendMsg("Control Flow Guard table seems to be empty.");
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
			if (value instanceof Address addr) {
				list.add(addr);
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
			DataType ibo32 = new IBO32DataType();
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
			log.appendMsg("Unable to label ControlFlowGuard IAT table: " + e.getMessage());
		}
	}

	/**
	 * Performs markup on a ControlFlowGuard function, if it exists.
	 * 
	 * @param label The ControFlowGuard label to create.
	 * @param description A short description of the ControlFlowGuard function type.
	 * @param functionPointerGetter A method that returns the ControlFlowGuard function's pointer
	 *   address.
	 * @param program The program.
	 * @param ntHeader The PE NTHeader.
	 * @param log The log.
	 */
	private static void markupCfgFunction(String label, String description,
			Supplier<Long> functionPointerGetter, Program program, NTHeader ntHeader,
			MessageLog log) {
		
		if (functionPointerGetter.get() == 0) {
			return;
		}

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Memory mem = program.getMemory();
		SymbolTable symbolTable = program.getSymbolTable();
		boolean is64bit = ntHeader.getOptionalHeader().is64bit();
		
		Address functionPointerAddr = space.getAddress(functionPointerGetter.get());
		PeUtils.createData(program, functionPointerAddr, PointerDataType.dataType, log);

		Address functionAddr;
		try {
			functionAddr = space.getAddress(
				is64bit ? mem.getLong(functionPointerAddr) : mem.getInt(functionPointerAddr));
		}
		catch (MemoryAccessException e) {
			log.appendMsg("Failed to read %s function pointer address at %s".formatted(description,
				functionPointerAddr));
			return;
		}

		try {
			symbolTable.createLabel(functionAddr, label, SourceType.IMPORTED);
		}
		catch (AddressOutOfBoundsException | InvalidInputException e) {
			log.appendMsg("Unable to apply label '%s' to %s function at %s: %s".formatted(label,
				description, functionAddr, e.getMessage()));
		}
		
		if (program.getListing().getDefinedDataAt(functionAddr) == null) {
			AbstractProgramLoader.markAsFunction(program, null, functionAddr);
		}
		else {
			log.appendMsg("Unable to mark %s as function at %s. Data is already defined there."
					.formatted(description, functionAddr));
		}
	}
}
