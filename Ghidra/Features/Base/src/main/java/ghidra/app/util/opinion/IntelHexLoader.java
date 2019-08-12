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

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class IntelHexLoader extends AbstractProgramLoader {

	public final static String INTEL_HEX_NAME = "Intel Hex";

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

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (MotorolaHexLoader.isPossibleHexFile(provider)) {
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

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
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
			processIntelHex(provider, options, log, prog, monitor);
			success = true;
		}
		catch (AddressOverflowException e) {
			throw new IOException(
				"Hex file specifies range greater than allowed address space - " + e.getMessage());
		}
		return success;
	}

	private void processIntelHex(ByteProvider provider, List<Option> options, MessageLog log,
			Program program, TaskMonitor monitor)
			throws IOException, AddressOverflowException, CancelledException {
		String blockName = getBlockName(options);
		boolean isOverlay = isOverlay(options);
		Address baseAddr = getBaseAddr(options);
		if (baseAddr == null) {
			baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		}

		if (blockName == null || blockName.length() == 0) {
			blockName = generateBlockName(program, isOverlay, baseAddr.getAddressSpace());
		}

		String line = null;
		int lineNum = 0;
		IntelHexMemImage memImage =
			new IntelHexMemImage(program.getAddressFactory().getDefaultAddressSpace(), baseAddr);

		try (BufferedReader in =
			new BufferedReader(new InputStreamReader(provider.getInputStream(0)))) {
			while ((line = in.readLine()) != null) {
				monitor.checkCanceled();

				lineNum++;
				if (lineNum % 1000 == 1) {
					monitor.setMessage("Reading in ... " + lineNum);
				}

				String msg = memImage.parseLine(line);
				if (msg != null) {
					log.appendMsg("Line: " + lineNum + " - " + msg);
				}
			}
		}

		String msg = memImage.createMemory(getName(), provider.getName(),
			isOverlay ? blockName : null, isOverlay, program, monitor);

		if (msg.length() > 0) {
			log.appendMsg(msg);
		}

		try {
			final SymbolTable symbolTable = program.getSymbolTable();
			final AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
			final long startEIP = memImage.getStartEIP();
			final int startCS = memImage.getStartCS();
			final int startIP = memImage.getStartIP();
			Address entryAddress = null;
			if (startEIP != -1) {
				entryAddress = space.getAddress(startEIP);
			}
			else if (startCS != -1 && startIP != -1) {
				if (space instanceof SegmentedAddressSpace) {
					SegmentedAddressSpace segSpace = (SegmentedAddressSpace) space;
					entryAddress = segSpace.getAddress(startCS, startIP);
				}
			}
			if (entryAddress != null) {
				createSymbol(symbolTable, entryAddress, "entry", true, null);
			}
		}
		catch (Exception e) {
			log.appendMsg("Could not create symbol at entry point: " + e);
		}
	}

	private void createSymbol(SymbolTable symbolTable, Address addr, String name, boolean isEntry,
			Namespace namespace) throws InvalidInputException {
		if (isEntry) {
			symbolTable.addExternalEntryPoint(addr);
		}
		symbolTable.createLabel(addr, name, namespace, SourceType.IMPORTED);
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
		return INTEL_HEX_NAME;
	}
}
