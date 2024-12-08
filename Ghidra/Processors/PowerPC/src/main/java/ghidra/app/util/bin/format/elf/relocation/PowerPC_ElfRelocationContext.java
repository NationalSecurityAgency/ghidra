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
package ghidra.app.util.bin.format.elf.relocation;

import java.math.BigInteger;
import java.util.Map;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

public class PowerPC_ElfRelocationContext
		extends ElfRelocationContext<PowerPC_ElfRelocationHandler> {

	private Integer sdaBase;
	private Integer sda2Base;

	protected PowerPC_ElfRelocationContext(PowerPC_ElfRelocationHandler handler,
			ElfLoadHelper loadHelper, Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, symbolMap);
	}

	/**
	 * Get or establish _SDA_BASE_ value and apply as r13 context value to all memory blocks
	 * with execute permission.
	 * @return _SDA_BASE_ offset or null if unable to determine or establish
	 */
	Integer getSDABase() {
		if (sdaBase != null) {
			if (sdaBase == -1) {
				return null;
			}
			return sdaBase;
		}
		sdaBase = getBaseOffset("_SDA_BASE_", ".sdata", ".sbss");
		if (sdaBase == -1) {
			getLog().appendMsg("ERROR: failed to establish _SDA_BASE_");
			return null;
		}
		setRegisterContext("r13", BigInteger.valueOf(sdaBase));
		return sdaBase;
	}

	/**
	 * Get or establish _SDA2_BASE_ value and apply as r2 context value to all memory blocks
	 * with execute permission.
	 * @return _SDA2_BASE_ offset or null if unable to determine or establish
	 */
	Integer getSDA2Base() {
		if (sda2Base != null) {
			if (sda2Base == -1) {
				return null;
			}
			return sda2Base;
		}
		sda2Base = getBaseOffset("_SDA2_BASE_", ".sdata2", ".sbss2");
		if (sda2Base == -1) {
			getLog().appendMsg("ERROR: failed to establish _SDA2_BASE_");
			return null;
		}
		setRegisterContext("r2", BigInteger.valueOf(sda2Base));
		return sda2Base;
	}

	/**
	 * Apply register context to all memory blocks which satisfy blockPredicate check.
	 * @param regName register name
	 * @param value context value
	 */
	private void setRegisterContext(String regName, BigInteger value) {
		Register reg = program.getRegister(regName);
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isExecute()) {
				try {
					program.getProgramContext()
							.setValue(reg, block.getStart(), block.getEnd(), value);
				}
				catch (ContextChangeException e) {
					throw new AssertException(e); // no instructions should exist yet
				}
			}
		}
	}

	/**
	 * Establish base offset from symbol or range of specified memory blocks.
	 * @param symbolName base symbol name
	 * @param blockNames block names which may be used to establish base range
	 * @return base offset or -1 on failure
	 */
	private Integer getBaseOffset(String symbolName, String... blockNames) {

		MessageLog log = getLog();

		Symbol baseSymbol = SymbolUtilities.getLabelOrFunctionSymbol(program, symbolName,
			msg -> log.appendMsg(msg));
		if (baseSymbol != null) {
			int baseOffset = (int) baseSymbol.getAddress().getOffset();
			String absString = "";
			if (baseSymbol.isPinned()) {
				absString = "absolute ";
			}
			log.appendMsg(
				"Using " + absString + symbolName + " of 0x" + Integer.toHexString(baseOffset));
			return baseOffset;
		}

		Memory mem = program.getMemory();
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		AddressSet blockSet = new AddressSet();
		for (String blockName : blockNames) {
			MemoryBlock block = mem.getBlock(blockName);
			if (block != null) {
				if (!block.getStart().getAddressSpace().equals(defaultSpace)) {
					log.appendMsg("ERROR: " + blockName + " not in default space");
					return -1;
				}
				blockSet.add(block.getStart(), block.getEnd());
			}
		}
		if (blockSet.isEmpty()) {
			return -1;
		}

		Address baseAddr = blockSet.getMinAddress();
		long range = blockSet.getMaxAddress().subtract(baseAddr) + 1;
		if (range > Short.MAX_VALUE) {
			// use aligned midpoint of range
			baseAddr = baseAddr.add((range / 2) & ~0x0f);
		}

		try {
			program.getSymbolTable().createLabel(baseAddr, symbolName, SourceType.ANALYSIS);
		}
		catch (InvalidInputException e) {
			throw new AssertException(e);
		}

		int baseOffset = (int) baseAddr.getOffset();
		log.appendMsg("Defined " + symbolName + " of 0x" + Integer.toHexString(baseOffset));
		return baseOffset;
	}

}
