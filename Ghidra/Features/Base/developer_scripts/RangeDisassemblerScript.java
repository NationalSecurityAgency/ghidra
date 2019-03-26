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
import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;

public class RangeDisassemblerScript extends GhidraScript {

	/**
	 * Required properties:
	 *  min - minimum disassembly address or block name
	 *  max - maximum disassembly address (not used if block name used for min)
	 *  out - disassembly output file path
	 * 
	 * Optional:
	 *  set.<context-reg-name>       - optional starting context value
	 *  set.range.<context-reg-name> - optional context value over range
	 * 
	 */

	private AddressSetView region;
	private File outFile;

	@Override
	protected void run() throws Exception {

		if (!isRunningHeadless()) {
			printerr("Script intended for Headless use only");
			return;
		}

		if (currentProgram == null) {
			printerr("Requires open program");
			return;
		}

		currentProgram.setTemporary(true);

		if (!processParameters()) {
			return;
		}

		Msg.info(this, "Disassmbly Output File: " + outFile.getAbsolutePath());

		PrintWriter out = new PrintWriter(outFile);
		try {
			disassembleRegion(out);
		}
		finally {
			out.close();
		}

	}

	private void disassembleRegion(PrintWriter out) {

		int alignment = currentProgram.getLanguage().getInstructionAlignment();

		Disassembler disassembler =
			Disassembler.getDisassembler(currentProgram, false, false, false, monitor, null);

		DumbMemBufferImpl memBuffer =
			new DumbMemBufferImpl(currentProgram.getMemory(), region.getMinAddress());

		ParallelInstructionLanguageHelper helper =
			currentProgram.getLanguage().getParallelInstructionHelper();

		int cnt = 0;

		for (AddressRange range : region.getAddressRanges(true)) {

			Address nextAddr = range.getMinAddress();

			InstructionBlock lastPseudoInstructionBlock = null;

			while (nextAddr != null && nextAddr.compareTo(range.getMaxAddress()) <= 0) {

				if ((nextAddr.getOffset() % alignment) != 0) {
					nextAddr = nextAddr.next();
					continue;
				}

				Instruction pseudoInstruction = null;
				InstructionError error = null;

				if (lastPseudoInstructionBlock != null) {
					pseudoInstruction = lastPseudoInstructionBlock.getInstructionAt(nextAddr);
					if (pseudoInstruction == null) {
						error = lastPseudoInstructionBlock.getInstructionConflict();
						if (error != null && !nextAddr.equals(error.getInstructionAddress())) {
							error = null;
						}
					}
				}

				if (pseudoInstruction == null && error == null) {
					memBuffer.setPosition(nextAddr);
					lastPseudoInstructionBlock =
						disassembler.pseudoDisassembleBlock(memBuffer, null, 1);
					if (lastPseudoInstructionBlock != null) {
						pseudoInstruction = lastPseudoInstructionBlock.getInstructionAt(nextAddr);
						if (pseudoInstruction == null) {
							error = lastPseudoInstructionBlock.getInstructionConflict();
							if (error != null && !nextAddr.equals(error.getInstructionAddress())) {
								error = null;
							}
						}
					}
				}

				try {
					if (pseudoInstruction != null) {
						out.print(nextAddr.toString());
						out.print(" ");
						out.print(formatBytes(pseudoInstruction.getBytes()));
						out.print(" ");

						String prefix = null;
						if (helper != null) {
							prefix = helper.getMnemonicPrefix(pseudoInstruction);
						}
						if (prefix == null) {
							prefix = "    ";
						}
						else {
							prefix = StringUtilities.pad(prefix, ' ', -4);
						}
						out.println(prefix);

						out.println(pseudoInstruction.toString());

						nextAddr = pseudoInstruction.getMaxAddress().next();
					}
					else {
						out.print(nextAddr.toString());
						out.print(" ");
						out.print(formatBytes(new byte[] { memBuffer.getByte(0) }));
						out.print(" ERROR: ");
						out.println(error.getConflictMessage());

						nextAddr = nextAddr.add(alignment);
					}

					if ((++cnt % 20000) == 0) {
						Msg.info(this, "Disassembled: " + cnt);
					}
				}
				catch (AddressOutOfBoundsException e) {
					nextAddr = null; // next range
				}
				catch (MemoryAccessException e) {
					out.print(nextAddr.toString());
					out.println(" ERROR: " + e.getMessage());
					break;
				}
			}
		}
		Msg.info(this, "Disassembled: " + cnt + " instructions to " + outFile);
	}

	private static final int MAX_BYTES = 4;

	private String formatBytes(byte[] bytes) {

		int totalWidth = (3 * 4) + 2;
		StringBuilder buf = new StringBuilder();

		for (int i = 0; i < bytes.length && i < MAX_BYTES; i++) {
			if (i != 0) {
				buf.append(' ');
			}
			int v = bytes[i] & 0xff;
			if (v < 0x10) {
				buf.append('0');
			}
			buf.append(Integer.toHexString(v));
		}
		if (bytes.length > MAX_BYTES) {
			buf.append('.');
		}

		return StringUtilities.pad(buf.toString(), ' ', -totalWidth);
	}

	private boolean processParameters() {

		Address minAddr = null;
		Address maxAddr = null;

		AddressFactory addrFactory = currentProgram.getAddressFactory();

		boolean missingParam = false;

		String minAddrStr = propertiesFileParams.getValue("min");
		if (minAddrStr == null) {
			printerr("Missing required minimum address property: min");
			missingParam = true;
		}
		else {
			minAddr = addrFactory.getAddress(minAddrStr);
			if (minAddr == null) {

				// Try as block name
				MemoryBlock block = currentProgram.getMemory().getBlock(minAddrStr);
				if (block == null) {
					printerr("Failed to parse min address/block: " + minAddrStr);
					missingParam = true;
				}
				else {
					minAddr = block.getStart();
					maxAddr = block.getEnd();
				}
			}
		}

		if (maxAddr == null) {
			String maxAddrStr = propertiesFileParams.getValue("max");
			if (minAddrStr == null) {
				printerr("Missing required maximum address property: max");
				missingParam = true;
			}
			else {
				maxAddr = addrFactory.getAddress(maxAddrStr);
				if (maxAddr == null) {
					printerr("Failed to parse max address: " + maxAddrStr);
					missingParam = true;
				}
			}
		}

		String filepath = propertiesFileParams.getValue("out");
		if (minAddrStr == null) {
			printerr("Missing required output file path property: out");
			missingParam = true;
		}
		else {
			outFile = new File(filepath);
			File parentDir = outFile.getParentFile();
			if (!parentDir.exists()) {
				printerr("Output directory not found: " + parentDir.getAbsolutePath());
				missingParam = true;
			}
		}

		if (missingParam) {
			return false;
		}

		if (!minAddr.hasSameAddressSpace(maxAddr) || minAddr.compareTo(maxAddr) > 0) {
			printerr("Invalid address range: " + minAddr + " - " + maxAddr);
			return false;
		}

		region =
			currentProgram.getMemory().getLoadedAndInitializedAddressSet().intersectRange(minAddr, maxAddr);

		if (region.isEmpty()) {
			printerr("Address range does not intersect initiailized memory: " + minAddr + " - " +
				maxAddr);
			return false;
		}

		ProgramContext programContext = currentProgram.getProgramContext();

		boolean badReg;
		try {
			badReg = false;
			for (String key : propertiesFileParams.keySet()) {
				boolean setRange = false;
				int index;
				if (key.startsWith("set.range.")) {
					setRange = true;
					index = 10;
				}
				else if (key.startsWith("set.")) {
					index = 4;
				}
				else {
					continue;
				}
				String regName = key.substring(index);
				Register reg = currentProgram.getRegister(regName);
				if (reg == null || !reg.isProcessorContext()) {
					printerr("Processor context register field not found: " + regName);
					badReg = true;
					continue;
				}

				BigInteger value;
				String valueStr = propertiesFileParams.getValue(key);
				try {
					value = BigInteger.valueOf(Long.parseLong(valueStr));
				}
				catch (NumberFormatException e) {
					printerr("Invalid register set value: " + valueStr);
					badReg = true;
					continue;
				}

				if (setRange) {
					programContext.setValue(reg, minAddr, maxAddr, value);
				}
				else {
					programContext.setValue(reg, minAddr, minAddr, value);
				}

			}
		}
		catch (ContextChangeException e) {
			printerr("Program must be clear of all code units!");
			printerr(e.getMessage());
			return false;
		}

		if (badReg) {
			return false;
		}

		return true;
	}
}
