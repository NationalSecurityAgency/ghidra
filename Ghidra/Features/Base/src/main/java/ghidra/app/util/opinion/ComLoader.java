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

package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing old-style DOS COM executables 
 */
public class ComLoader extends AbstractLibrarySupportLoader {

	public final static String COM_NAME = "Old-style DOS Executable (COM)";

	private final static String ENTRY_NAME = "entry";
	private final static int PSP_START_ADDRESS = 0x0;
	private final static int COM_START_ADDRESS = 0x100;
	private final static int COM_MAX_LEN = 0xff00; // 0xFFFF - 0xFF (PSP size)
	private static final int SCORE_THRESHOLD = 12; // for score system

	@Override
	public String getName() {
		return COM_NAME;
	}

	@Override
	public boolean isFallback() {
		return true;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {

		List<LoadSpec> specs = new ArrayList<>();

		if (!provider.getName().toLowerCase().endsWith(".com")) {
			return specs;
		}

		long len = provider.length();
		if (len == 0 || len > COM_MAX_LEN) {
			return specs;
		}

		byte[] bytes = provider.readBytes(0, len);
		int[] data = new int[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			data[i] = Byte.toUnsignedInt(bytes[i]);
		}

		// Reject MZ executables
		if (data.length > 1 && data[0] == 'M' && data[1] == 'Z') {
			return specs;
		}

		int score = calculateScore(data);

		if (score >= SCORE_THRESHOLD) {
			specs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair("x86:LE:16:Real Mode", "default"), true));
		}

		return specs;
	}

	private int calculateScore(int[] data) {

		int score = 0;

		for (int i = 0; i < data.length - 2 && score < SCORE_THRESHOLD; i++) {

			// INT
			if (data[i] != 0xCD) {
				continue;
			}

			// INT 21h (DOS services)
			if (data[i + 1] == 0x21) {
				score += 2;

				// MOV AH, imm8 or MOV AL, imm8 before INT 21h
				if (i >= 2 && (data[i - 2] == 0xB4 || data[i - 2] == 0xB0)) {
					score += 3;
				}

				// MOV AX, imm16 before INT 21h
				if (i >= 3 && data[i - 3] == 0xB8) {
					score += 2;
				}

				if (score >= SCORE_THRESHOLD) {
					return score;
				}
			}

			// INT 20h (program terminate)
			else if (data[i + 1] == 0x20) {
				score += 2;

				if (score >= SCORE_THRESHOLD) {
					return score;
				}
			}

			// Other INT patterns preceded by register setup
			if (i > 1 && (data[i - 2] == 0xB4 || data[i - 2] == 0xB0)) {
				score += 2;
			}
			if (i > 2 && data[i - 3] == 0xB8) {
				score += 2;
			}
			if (score >= SCORE_THRESHOLD) {
				return score;
			}
		}

		// Only attempt string heuristic if needed
		int dollarStrings = countDollarStrings(data);
		if (dollarStrings > 0) {
			score += 3;
		}
		if (dollarStrings > 2) {
			score += 2;
		}

		return score;
	}

	/**
	 * Counts occurrences of DOS-style "$"-terminated strings.
	 * <p>
	 * In DOS COM programs, function AH=09h (INT 21h) prints a string
	 * terminated by '$'. Therefore, COM binaries frequently contain
	 * printable ASCII sequences followed by '$'.
	 * <p>
	 * This heuristic looks for printable ASCII runs of length >= 4
	 * followed by '$'. The scan is limited to a small prefix of the file
	 * for performance, since this method runs on every file imported.
	 */
	private int countDollarStrings(int[] data) {

		int count = 0;
		int minLen = 4;

		for (int i = 0; i < data.length - minLen && count < 3; i++) {

			int len = 0;

			while (i + len < data.length && isPrintable(data[i + len])) {
				len++;

				if (i + len < data.length && data[i + len] == '$' && len >= minLen) {
					count++;
					i += len; // skip ahead
					break;
				}
			}
		}

		return count;
	}

	private boolean isPrintable(int b) {
		return b >= 0x20 && b <= 0x7E;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws IOException, CancelledException {

		ByteProvider provider = settings.provider();
		TaskMonitor monitor = settings.monitor();
		MessageLog log = settings.log();

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		try {
			// Create PSP block at 0000h
			MemoryBlockUtils.createInitializedBlock(program, false, "PSP",
				space.getAddress(PSP_START_ADDRESS), 0x100, "PSP",
				null, true, true, false, log);

			FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

			// Create CODE block at 0100h
			MemoryBlockUtils.createInitializedBlock(program, false, "CODE",
				space.getAddress(COM_START_ADDRESS), fileBytes, 0,
				provider.length(), "COM Code", null, true, true, false, log);

		}
		catch (Exception e) {
			log.appendMsg("Failed to create blocks");
		}

		// Create entry point
		SymbolTable symbolTable = program.getSymbolTable();
		try {
			Address addr = space.getAddress(COM_START_ADDRESS);
			symbolTable.createLabel(addr, ENTRY_NAME, SourceType.IMPORTED);
			symbolTable.addExternalEntryPoint(addr);
		}
		catch (InvalidInputException e) {
			log.appendMsg("Failed to process entry point");
		}
	}
}
