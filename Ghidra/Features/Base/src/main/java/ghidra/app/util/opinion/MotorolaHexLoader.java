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

import java.io.*;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class MotorolaHexLoader extends AbstractProgramLoader {

	public final static String MOTOROLA_HEX_NAME = "Motorola Hex";

	@Override
	public LoaderTier getTier() {
		return LoaderTier.UNTARGETED_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}

	private static final String OPTION_NAME_BASE_ADDRESS = "Base Address";
	private static final String OPTION_NAME_BLOCK_NAME = "Block Name";
	private static final String OPTION_NAME_IS_OVERLAY = "Overlay";

	private final static int BUFSIZE = 64 * 1024;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (isPossibleHexFile(provider)) {
			List<LanguageDescription> languageDescriptions =
				getLanguageService().getLanguageDescriptions(false);
			for (LanguageDescription languageDescription : languageDescriptions) {
				Collection<CompilerSpecDescription> compilerSpecDescriptions =
					languageDescription.getCompatibleCompilerSpecDescriptions();
				for (CompilerSpecDescription compilerSpecDescription : compilerSpecDescriptions) {
					LanguageCompilerSpecPair lcs =
						new LanguageCompilerSpecPair(languageDescription.getLanguageID(),
							compilerSpecDescription.getCompilerSpecID());
					loadSpecs.add(new LoadSpec(this, 0, lcs, false));
				}
			}
		}
		return loadSpecs;
	}

	static boolean isPossibleHexFile(ByteProvider provider) {
		try (BoundedBufferedReader reader =
			new BoundedBufferedReader(new InputStreamReader(provider.getInputStream(0)))) {
			String line = reader.readLine();
			while (line.matches("^\\s*$")) {
				line = reader.readLine();
			}
			return line.matches("^[S:][0-9a-fA-F]+$");
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		Address baseAddr = null;

		for (Option option : options) {
			String optName = option.getName();
			try {
				if (optName.equals(OPTION_NAME_BASE_ADDRESS)) {
					baseAddr = (Address) option.getValue();
					if (baseAddr == null) {
						return "Invalid base address";
					}
				}
				else if (optName.equals(OPTION_NAME_BLOCK_NAME)) {
					if (!String.class.isAssignableFrom(option.getValueClass())) {
						return OPTION_NAME_BLOCK_NAME + " must be a String";
					}
				}
				else if (optName.equals(OPTION_NAME_IS_OVERLAY)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return OPTION_NAME_IS_OVERLAY + " must be a boolean";
					}
				}
				else {
					return "Unknown option: " + optName;
				}
			}
			catch (ClassCastException e) {
				return "Invalid type for option: " + optName + " - " + e.getMessage();
			}
		}
		return null;
	}

	private Address getBaseAddr(List<Option> options) {
		Address baseAddr = null;
		for (Option option : options) {
			String optName = option.getName();
			if (optName.equals(OPTION_NAME_BASE_ADDRESS)) {
				baseAddr = (Address) option.getValue();
			}
		}
		return baseAddr;
	}

	private String getBlockName(List<Option> options) {
		String blockName = "";
		for (Option option : options) {
			String optName = option.getName();
			if (optName.equals(OPTION_NAME_BLOCK_NAME)) {
				blockName = (String) option.getValue();
			}
		}
		return blockName;
	}

	private boolean isOverlay(List<Option> options) {
		boolean isOverlay = false;
		for (Option option : options) {
			String optName = option.getName();
			if (optName.equals(OPTION_NAME_IS_OVERLAY)) {
				isOverlay = (Boolean) option.getValue();
			}
		}
		return isOverlay;
	}

	@Override
	protected List<Program> loadProgram(ByteProvider provider, String programName,
			DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Object consumer, TaskMonitor monitor) throws IOException, CancelledException {
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec importerCompilerSpec =
			importerLanguage.getCompilerSpecByID(pair.compilerSpecID);

		Program prog = createProgram(provider, programName, null, getName(), importerLanguage,
			importerCompilerSpec, consumer);
		boolean success = false;
		try {
			success = loadInto(provider, loadSpec, options, log, prog, monitor);
			if (success) {
				createDefaultMemoryBlocks(prog, importerLanguage, log);
			}
		}
		finally {
			if (!success) {
				prog.release(consumer);
				prog = null;
			}
		}
		List<Program> results = new ArrayList<Program>();
		if (prog != null) {
			results.add(prog);
		}
		return results;
	}

	@Override
	protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Program prog, TaskMonitor monitor)
			throws IOException, CancelledException {
		Address baseAddr = getBaseAddr(options);

		if (baseAddr == null) {
			baseAddr = prog.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		}
		boolean success = false;
		try {
			processMotorolaHex(provider, options, prog, baseAddr, monitor);
			success = true;
		}
		catch (AddressOverflowException e) {
			throw new IOException(
				"Hex file specifies range greater than allowed address space - " + e.getMessage());
		}
		return success;
	}

	private void processMotorolaHex(ByteProvider provider, List<Option> options, Program program,
			Address baseAddr, TaskMonitor monitor)
			throws IOException, AddressOverflowException, CancelledException {
		String blockName = getBlockName(options);
		boolean isOverlay = isOverlay(options);

		if (blockName == null || blockName.length() == 0) {
			blockName = generateBlockName(program, isOverlay, baseAddr.getAddressSpace());
		}

		long startAddress = 0;
		long endAddress = 0;
		int offset = 0;
		String line;
		int lineNum = 0;
		byte[] dataBuffer = new byte[BUFSIZE];
		int counter = 0;
		MessageLog log = new MessageLog();
		try (BufferedReader in =
			new BufferedReader(new InputStreamReader(provider.getInputStream(0)))) {
			while ((line = in.readLine()) != null) {

				monitor.checkCanceled();

				int index = 0;
				int checkSum = 0;
				int temp;
				int addrLen = 0;
				// keep track of line number we are on
				lineNum++;
				// remove white space from both ends of line string
				line = line.trim();

				if (line.length() < 10) {
					String msg = provider.getName() + ", line: " + lineNum + " is too short";
					continue;
				}

				// check for a valid start record if line isn't valid skip it go
				// on to next
				if (line.charAt(index++) != 'S' && line.charAt(index++) != 's') {
					String msg = "Line #" + (lineNum - 1) + " is not valid\n";
					continue;
				}

				int finished = 0;
				int skipline = 0;
				// get record type
				int record_type = line.charAt(index++);
				// get # bytes

				temp = getByte(line, index);
				index += 2;
				checkSum += temp;

				int numBytes = temp;

				switch (record_type) {
					case '9': // end of record for 16 bit address type
					case '8': // end of record for 24 bit address type
					case '7': // end of record for 32 bit address type
						finished = 1;
						break;
					case '1': // start of record for 16 bit address type
						addrLen = 2;
						break;
					case '2': // start of record for 24 bit address type
						addrLen = 3;
						break;
					case '3': // start of record for 32 bit address type
						addrLen = 4;
						break;
					case '0':
						skipline = 1;
						break;
					default:
						String msg = "Line #" + (lineNum - 1) + " is not valid\n";
						skipline = 1;
						break;
				}
				if (finished == 1) {
					break; // quit if reached end record
				}
				if (skipline == 1) {
					continue; // skip this line and go to next line
				}
				// add address bytes to checksum
				try {
					for (int i = 0; i < addrLen; i++) {
						checkSum += getByte(line, index + i * 2);
					}
				}
				catch (IndexOutOfBoundsException exc) {
					String msg = provider.getName() + ", line: " + lineNum + " line length problem";
					skipline = 1;
				}
				if (skipline == 1) {
					continue; // skip this line and go to next line
				}
				// get address
				// read it in as a hex string, convert
				String addrStr = line.substring(4, 4 + 2 * addrLen);

				counter++;
				if (counter % 1000 == 0) {
					monitor.setMessage("Reading in ... " + addrStr);
				}
				// get hex address value and move index passed address
				long addr = NumericUtilities.parseHexLong(addrStr);
				index += 2 * addrLen;
				if (lineNum == 1) {
					startAddress = addr;
				}
				// if this line isn't contiguous to current block in buffer
				// add current block to memory and start new block at addr
				if (addr != endAddress || (offset + numBytes) > BUFSIZE) {

					if (offset != 0) {
						byte[] data = new byte[offset];
						System.arraycopy(dataBuffer, 0, data, 0, offset);

						Address start = baseAddr.add(startAddress);

						String name =
							blockName == null ? baseAddr.getAddressSpace().getName() : blockName;
						MemoryBlockUtils.createInitializedBlock(program, isOverlay, name, start,
							new ByteArrayInputStream(data), data.length, "", provider.getName(),
							true, isOverlay, isOverlay, log, monitor);
					}
					offset = 0;
					// set up new start address of new block we are starting
					startAddress = addr;
					endAddress = addr;
				}
				// update end address to start of next contiguous line address
				endAddress += numBytes - addrLen - 1;

				// read in the data bytes on the line
				for (int i = 0; i < numBytes - addrLen - 1; i++) {
					try {
						temp = getByte(line, index);
						index += 2;
						checkSum += temp;
					}
					catch (NumberFormatException exc) {
						String msg = provider.getName() + ", line: " + lineNum +
							" number format at byte #" + i;
						skipline = 1;

					}
					catch (IndexOutOfBoundsException exc) {
						String msg =
							provider.getName() + ", line: " + lineNum + " line length problem";
						skipline = 1;
					}
					if (skipline != 1) {
						dataBuffer[i + offset] = (byte) temp;
					}
				}
				if (skipline == 1) {
					continue; // skip this line and go to next line
				}
				offset += numBytes - addrLen - 1;

				// is the checksum OK?
				try {
					temp = getByte(line, index);
					index += 2;
				}
				catch (IndexOutOfBoundsException exc) {
					String msg = provider.getName() + ", line: " + lineNum + " line length problem";
					skipline = 1;
				}
				if (skipline == 1) {
					continue; // skip this line and go to next line
				}
			}

			// if any data in block, add it to memory
			if (offset != 0) {
				byte[] data = new byte[offset];
				System.arraycopy(dataBuffer, 0, data, 0, offset);

				String name = baseAddr.getAddressSpace().getName();
				Address start = baseAddr.add(startAddress);

				name = blockName;
				int count = 0;
				while (true) {
					try {
						MemoryBlockUtils.createInitializedBlock(program, isOverlay, blockName,
							start, new ByteArrayInputStream(data), data.length, "",
							provider.getName(), true, true, true, log, monitor);
						break;
					}
					catch (RuntimeException e) {
						Throwable cause = e.getCause();
						if (!(cause instanceof DuplicateNameException)) {
							throw e;
						}
						++count;
						name = blockName + "_" + count;
					}
				}
			}
		}
	}

	/**
	 * Returns a byte at the index in the line, formatted as an int.
	 */
	private int getByte(String line, int index) {
		int value;

		String byteString = line.substring(index, index + 2);
		value = Integer.parseInt(byteString, 16);
		return value;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		String blockName = "";
		boolean isOverlay = false;
		Address baseAddr = null;
		if (domainObject instanceof Program) {
			Program program = (Program) domainObject;
			AddressFactory addressFactory = program.getAddressFactory();
			if (addressFactory != null) {
				AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
				if (defaultAddressSpace != null) {
					baseAddr = defaultAddressSpace.getAddress(0);
				}
			}
		}

		ArrayList<Option> list = new ArrayList<Option>();

		if (loadIntoProgram) {
			list.add(new Option(OPTION_NAME_IS_OVERLAY, isOverlay));
			list.add(new Option(OPTION_NAME_BLOCK_NAME, blockName));
		}
		else {
			isOverlay = false;
		}
		if (baseAddr == null) {
			list.add(new Option(OPTION_NAME_BASE_ADDRESS, Address.class));
		}
		else {
			list.add(new Option(OPTION_NAME_BASE_ADDRESS, baseAddr));
		}
		return list;
	}

	@Override
	public String getName() {
		return MOTOROLA_HEX_NAME;
	}

}
