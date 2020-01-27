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

import ghidra.app.util.*;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BinaryLoader extends AbstractProgramLoader {

	public final static String BINARY_NAME = "Raw Binary";

	public static final String OPTION_NAME_LEN = "Length";
	public static final String OPTION_NAME_FILE_OFFSET = "File Offset";
	public static final String OPTION_NAME_BASE_ADDR = "Base Address";
	public static final String OPTION_NAME_BLOCK_NAME = "Block Name";
	public static final String OPTION_NAME_IS_OVERLAY = "Overlay";

	@Override
	public LoaderTier getTier() {
		return LoaderTier.UNTARGETED_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 100;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
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
		return loadSpecs;
	}

	private static Long parseLong(Option option) {
		Object value = option.getValue();
		if (value == null) {
			return null;
		}
		String rendered = value.toString();
		if (rendered.toLowerCase().startsWith("0x")) {
			rendered = rendered.substring(2);
		}
		return NumericUtilities.parseHexLong(rendered);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		Address baseAddr = null;
		long length = 0;
		long fileOffset = 0;
		long origFileLength;
		boolean isOverlay = false;
		try {
			origFileLength = provider.length();
		}
		catch (IOException e) {
			return "Error determining length: " + e.getMessage();
		}

		for (Option option : options) {
			String optName = option.getName();
			try {
				if (optName.equals(OPTION_NAME_BASE_ADDR)) {
					baseAddr = (Address) option.getValue();
				}
			}
			catch (Exception e) {
				if (e instanceof OptionException) {
					return e.getMessage();
				}
				return "Invalid value for " + optName + " - " + option.getValue();
			}
		}
		if (baseAddr == null) {
			return "Invalid base address";
		}

		for (Option option : options) {
			String optName = option.getName();
			try {
				if (optName.equals(OPTION_NAME_BASE_ADDR)) {
					// skip - handled above
				}
				else if (optName.equals(OPTION_NAME_FILE_OFFSET)) {
					try {
						fileOffset = parseLong(option);
					}
					catch (Exception e) {
						fileOffset = -1;
					}
					if (fileOffset < 0 || fileOffset >= origFileLength) {
						return "File Offset must be greater than 0 and less than file length " +
							origFileLength + " (0x" + Long.toHexString(origFileLength) + ")";
					}
				}
				else if (optName.equals(OPTION_NAME_LEN)) {
					try {
						length = parseLong(option);
					}
					catch (Exception e) {
						length = -1;
					}
					if (length < 0 || length > origFileLength) {
						return "Length must be greater than 0 and less than or equal to file length " +
							origFileLength + " (0x" + Long.toHexString(origFileLength) + ")";
					}

					long baseOffset = baseAddr.getOffset();
					AddressSpace space = baseAddr.getAddressSpace();
					long maxLength = Memory.MAX_BINARY_SIZE;
					if (space.getSize() < 64) {
						maxLength =
							Math.min(maxLength, space.getMaxAddress().getOffset() + 1 - baseOffset);
					}
					else if (baseOffset < 0 && baseOffset > -Memory.MAX_BINARY_SIZE) {
						maxLength = -baseAddr.getOffset();
					}
					if (length > maxLength) {
						return "Length must not exceed maximum allowed size of " + maxLength +
							" (0x" + Long.toHexString(maxLength) + ") bytes";
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
					isOverlay = (boolean) option.getValue();
				}
			}
			catch (Exception e) {
				if (e instanceof OptionException) {
					return e.getMessage();
				}
				return "Invalid value for " + optName + " - " + option.getValue();
			}
		}
		if (fileOffset + length > origFileLength) {
			return "File Offset + Length (0x" + Long.toHexString(fileOffset + length) +
				") too large; set length to 0x" + Long.toHexString(origFileLength - fileOffset);
		}
		if (fileOffset == -1) {
			return "Invalid file offset specified";
		}
		if (length == -1) {
			return "Invalid length specified";
		}
		if (program != null) {
			if (program.getMemory().intersects(baseAddr, baseAddr.add(length - 1)) && !isOverlay) {
				return "Memory Conflict: Use <Options...> to change the base address!";
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	private Address getBaseAddr(List<Option> options) {
		Address baseAddr = null;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(OPTION_NAME_BASE_ADDR)) {
					baseAddr = (Address) option.getValue();
				}
			}
		}
		return baseAddr;
	}

	private long getLength(List<Option> options) {
		long length = 0;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(OPTION_NAME_LEN)) {
					length = parseLong(option);
				}
			}
		}
		return length;
	}

	private long getFileOffset(List<Option> options) {
		long fileOffset = 0;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(OPTION_NAME_FILE_OFFSET)) {
					fileOffset = parseLong(option);
				}
			}
		}
		return fileOffset;
	}

	private String getBlockName(List<Option> options) {
		String blockName = "";
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(OPTION_NAME_BLOCK_NAME)) {
					blockName = (String) option.getValue();
				}
			}
		}
		return blockName;
	}

	private boolean isOverlay(List<Option> options) {
		boolean isOverlay = false;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(OPTION_NAME_IS_OVERLAY)) {
					isOverlay = (Boolean) option.getValue();
				}
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

		Address baseAddr =
			importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		Program prog = createProgram(provider, programName, baseAddr, getName(), importerLanguage,
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
		long length = getLength(options);
		//File file = provider.getFile();
		long fileOffset = getFileOffset(options);
		Address baseAddr = getBaseAddr(options);
		String blockName = getBlockName(options);
		boolean isOverlay = isOverlay(options);

		if (length == 0) {
			length = provider.length();
		}

		length = clipToMemorySpace(length, log, prog);

		FileBytes fileBytes =
			MemoryBlockUtils.createFileBytes(prog, provider, fileOffset, length, monitor);
		try {
			AddressSpace space = prog.getAddressFactory().getDefaultAddressSpace();
			if (baseAddr == null) {
				baseAddr = space.getAddress(0);
			}
			if (blockName == null || blockName.length() == 0) {
				blockName = generateBlockName(prog, isOverlay, baseAddr.getAddressSpace());
			}
			createBlock(prog, isOverlay, blockName, baseAddr, fileBytes, length, log);

			return true;
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException("Invalid address range specified: start:" +
				baseAddr + ", length:" + length + " - end address exceeds address space boundary!");
		}
	}

	private void createBlock(Program prog, boolean isOverlay, String blockName, Address baseAddr,
			FileBytes fileBytes, long length, MessageLog log)
			throws AddressOverflowException, IOException {

		if (prog.getMemory().intersects(baseAddr, baseAddr.add(length - 1)) && !isOverlay) {
			throw new IOException("Can't load " + length + " bytes at address " + baseAddr +
				" since it conflicts with existing memory blocks!");
		}
		MemoryBlockUtils.createInitializedBlock(prog, isOverlay, blockName, baseAddr, fileBytes, 0,
			length, null, "Binary Loader", true, !isOverlay, !isOverlay, log);

	}

	private long clipToMemorySpace(long length, MessageLog log, Program program) {
		AddressSpace defaultAddressSpace = program.getAddressFactory().getDefaultAddressSpace();
		long maxLength = defaultAddressSpace.getMaxAddress().getOffset() + 1;
		if (maxLength > 0 && length > maxLength) {
			log.appendMsg("Clipped file to fit into memory space");
			length = maxLength;
		}
		return length;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		long fileOffset = 0;
		long origFileLength = -1;
		try {
			origFileLength = provider.length();
		}
		catch (IOException e) {
			Msg.warn(this, "Error determining length", e);
		}
		long length = origFileLength;
		boolean isOverlay = false;
		String blockName = "";
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

		long tempLength = origFileLength - fileOffset;
		long len = Math.min(tempLength, origFileLength);
		len = Math.min(length, len);
		length = len;
		List<Option> list = new ArrayList<Option>();

		if (loadIntoProgram) {
			list.add(new Option(OPTION_NAME_IS_OVERLAY, isOverlay));
		}
		else {
			isOverlay = false;
		}
		list.add(new Option(OPTION_NAME_BLOCK_NAME, blockName, String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-blockName"));
		list.add(new Option(OPTION_NAME_BASE_ADDR, baseAddr, Address.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"));
		list.add(new Option(OPTION_NAME_FILE_OFFSET, new HexLong(fileOffset), HexLong.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-fileOffset"));
		list.add(new Option(OPTION_NAME_LEN, new HexLong(length), HexLong.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-length"));

		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram));
		return list;
	}

	@Override
	public String getName() {
		return BinaryLoader.BINARY_NAME;
	}

	@Override
	public boolean shouldApplyProcessorLabelsByDefault() {
		return true;
	}
}
