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

import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.pdb.PdbInfoCodeView;
import ghidra.app.util.bin.format.pdb.PdbInfoDotNet;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.debug.*;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Conv;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

abstract class AbstractPeDebugLoader extends AbstractOrdinalSupportLoader {

	/** Loader option to display line numbers */
	public static final String SHOW_LINE_NUMBERS_OPTION_NAME = "Show Debug Line Number Comments";
	static final boolean SHOW_LINE_NUMBERS_OPTION_DEFAULT = false;

	private HashMap<Address, StringBuffer> plateCommentMap = new HashMap<>();
	private HashMap<Address, StringBuffer> preCommentMap = new HashMap<>();
	private HashMap<Address, StringBuffer> postCommentMap = new HashMap<>();
	private HashMap<Address, StringBuffer> eolCommentMap = new HashMap<>();

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		list.add(new Option(SHOW_LINE_NUMBERS_OPTION_NAME, SHOW_LINE_NUMBERS_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-showDebugLineNumbers"));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(SHOW_LINE_NUMBERS_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	private boolean shouldShowDebugLineNumbers(List<Option> options) {
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(SHOW_LINE_NUMBERS_OPTION_NAME)) {
					return (Boolean) option.getValue();
				}
			}
		}
		return SHOW_LINE_NUMBERS_OPTION_DEFAULT;
	}

	protected void processComments(Listing listing, TaskMonitor monitor) {
		List<HashMap<Address, StringBuffer>> maps = new ArrayList<>();
		maps.add(plateCommentMap);
		maps.add(preCommentMap);
		maps.add(postCommentMap);
		maps.add(eolCommentMap);

		int[] types = new int[] { CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT,
			CodeUnit.POST_COMMENT, CodeUnit.EOL_COMMENT };
		String[] typeNames = new String[] { "PLATE", "PRE", "POST", "EOL" };
		int index = 0;
		for (HashMap<Address, StringBuffer> map : maps) {
			List<Address> list = convertSetToSortedList(map.keySet());
			for (Address addr : list) {
				if (monitor.isCancelled()) {
					break;
				}
				monitor.setMessage("Setting " + typeNames[index] + " comments at " + addr);
				StringBuffer buffer = map.get(addr);
				if (buffer != null) {
					listing.setComment(addr, types[index], buffer.toString());
				}
			}
			if (monitor.isCancelled()) {
				break;
			}
			++index;
		}
		for (HashMap<Address, StringBuffer> map : maps) {
			map.clear();
		}
	}

	private List<Address> convertSetToSortedList(Set<Address> set) {
		List<Address> list = new ArrayList<>(set);
		Collections.sort(list);
		return list;
	}

	protected void processDebug(DebugDirectoryParser parser, NTHeader ntHeader,
			Map<SectionHeader, Address> sectionToAddress, Program program, List<Option> options,
			TaskMonitor monitor) {

		if (parser == null) {
			return;
		}

		monitor.setMessage("Processing misc debug...");
		processDebugMisc(program, parser.getDebugMisc());

		monitor.setMessage("Processing fixup debug...");
		processDebugFixup(parser.getDebugFixup());

		monitor.setMessage("Processing code view debug...");
		processDebugCodeView(parser.getDebugCodeView(), ntHeader, sectionToAddress, program,
			options, monitor);

		monitor.setMessage("Processing coff debug...");
		processDebugCOFF(parser.getDebugCOFFSymbolsHeader(), ntHeader, sectionToAddress, program,
			options, monitor);
	}

	private void processDebugCodeView(DebugCodeView dcv, NTHeader ntHeader,
			Map<SectionHeader, Address> sectionToAddress, Program program, List<Option> options,
			TaskMonitor monitor) {

		if (dcv == null) {
			return;
		}

		Options proplist = program.getOptions(Program.PROGRAM_INFO);

		PdbInfoCodeView cvPdbInfo = dcv.getPdbInfo();
		if (cvPdbInfo != null) {
			cvPdbInfo.serializeToOptions(proplist);
		}

		PdbInfoDotNet dotnetPdbInfo = dcv.getDotNetPdbInfo();
		if (dotnetPdbInfo != null) {
			dotnetPdbInfo.serializeToOptions(proplist);
		}

		DebugCodeViewSymbolTable dcvst = dcv.getSymbolTable();
		if (dcvst == null) {
			return;
		}

		FileHeader fileHeader = ntHeader.getFileHeader();
		List<OMFSrcModule> srcModules = dcvst.getOMFSrcModules();
		for (OMFSrcModule module : srcModules) {
			OMFSrcModuleFile[] files = module.getOMFSrcModuleFiles();
			for (OMFSrcModuleFile file : files) {
				processFiles(file, module.getSegments(), fileHeader, sectionToAddress, monitor);
				processLineNumbers(fileHeader, sectionToAddress, file.getOMFSrcModuleLines(),
					options, monitor);

				if (monitor.isCancelled()) {
					return;
				}
			}
			if (monitor.isCancelled()) {
				return;
			}
		}

		/*TODO
		List<OMFSegMap> segMaps = dcvst.getOMFSegMaps();
		for (OMFSegMap map : segMaps) {
			if (monitor.isCancelled()) return;
		}
		*/

		/*TODO
		List<OMFModule> modules = dcvst.getOMFModules();
		for (OMFModule module : modules) {
			OMFSegDesc [] descs = module.getOMFSegDescs();
			for (OMFSegDesc desc : descs) {
				if (monitor.isCancelled()) return;
			}
			if (monitor.isCancelled()) return;
		}
		*/

		SymbolTable symTable = program.getSymbolTable();

		int errorCount = 0;
		List<OMFGlobal> globals = dcvst.getOMFGlobals();
		for (OMFGlobal global : globals) {
			List<DebugSymbol> symbols = global.getSymbols();
			for (DebugSymbol symbol : symbols) {
				if (monitor.isCancelled()) {
					return;
				}

				String name = symbol.getName();
				if (name == null) {
					continue;
				}

				short segVal = symbol.getSection();
				int offVal = symbol.getOffset();
				if (segVal == 0 && offVal == 0) {
					continue;
				}

				Address address = sectionToAddress.get(fileHeader.getSectionHeader(segVal - 1));
				if (address != null) {
					address = address.add(Conv.intToLong(offVal));

					try {
						symTable.createLabel(address, name, SourceType.IMPORTED);
					}
					catch (InvalidInputException e) {
						Msg.error(this, "Error creating label " + name + "at address " + address +
							": " + e.getMessage());
					}

					demangle(address, name, program);
				}
				else {
					++errorCount;
				}
			}
		}

		if (errorCount != 0) {
			Msg.error(this, "Failed to apply " + errorCount +
				" debug Code View symbols contained within unknown sections.");
		}
	}

	private void demangle(Address address, String name, Program program) {
		StringBuilder builder = new StringBuilder();
		try {
			List<DemangledObject> demangledObjects = DemanglerUtil.demangle(program, name, address);
			for (DemangledObject demangledObj : demangledObjects) {
				if (builder.length() > 0) {
					builder.append("\t");
				}
				builder.append(demangledObj.getSignature(true));
			}
		}
		catch (Exception e) {
			//log.appendMsg("Unable to demangle: "+name);
		}
		if (builder.length() > 0) {
			setComment(CodeUnit.PLATE_COMMENT, address, builder.toString());
		}
	}

	private void processFiles(OMFSrcModuleFile file, short[] segments, FileHeader fileHeader,
			Map<SectionHeader, Address> sectionToAddress, TaskMonitor monitor) {

		int[] starts = file.getStarts();
		int[] ends = file.getEnds();

		for (int k = 0; k < starts.length; ++k) {
			if (starts[k] == 0 || ends[k] == 0 || k >= segments.length) {
				continue;
			}

			Address addr = sectionToAddress.get(fileHeader.getSectionHeader(segments[k] - 1));
			if (addr == null) {
				continue;
			}

			Address startAddr = addr.add(Conv.intToLong(starts[k]));
			String cmt = "START-> " + file.getName() + ": " + "?";
			setComment(CodeUnit.PRE_COMMENT, startAddr, cmt);

			Address endAddr = addr.add(Conv.intToLong(ends[k]));
			cmt = "END-> " + file.getName() + ": " + "?";
			setComment(CodeUnit.PRE_COMMENT, endAddr, cmt);

			if (monitor.isCancelled()) {
				return;
			}
		}
	}

	private void processLineNumbers(FileHeader fileHeader,
			Map<SectionHeader, Address> sectionToAddress, OMFSrcModuleLine[] lines,
			List<Option> options, TaskMonitor monitor) {//TODO revisit this method for accuracy
		if (!shouldShowDebugLineNumbers(options)) {
			return;
		}
		for (OMFSrcModuleLine line : lines) {
			if (monitor.isCancelled()) {
				return;
			}
			Address addr =
				sectionToAddress.get(fileHeader.getSectionHeader(line.getSegmentIndex() - 1));
			if (addr != null) {
				int[] offsets = line.getOffsets();
				short[] lineNumbers = line.getLinenumbers();
				for (int j = 0; j < offsets.length; j++) {
					if (monitor.isCancelled()) {
						return;
					}
					if (offsets[j] > 0) {
						addLineComment(addr.add(Conv.intToLong(offsets[j])),
							Conv.shortToInt(lineNumbers[j]));
					}
				}
			}
		}
	}

	private void processDebugCOFF(DebugCOFFSymbolsHeader dcsh, NTHeader ntHeader,
			Map<SectionHeader, Address> sectionToAddress, Program program, List<Option> options,
			TaskMonitor monitor) {
		if (dcsh == null) {
			return;
		}
		DebugCOFFSymbolTable dcst = dcsh.getSymbolTable();
		if (dcst == null) {
			return;
		}
		DebugCOFFSymbol[] symbols = dcst.getSymbols();
		int errorCount = 0;
		for (DebugCOFFSymbol symbol : symbols) {
			if (monitor.isCancelled()) {
				return;
			}
			if (!processDebugCoffSymbol(symbol, ntHeader, sectionToAddress, program, monitor)) {
				++errorCount;
			}
		}

		if (errorCount != 0) {
			Msg.error(this, "Failed to apply " + errorCount +
				" debug COFF symbols contained within unknown sections.");
		}

		DebugCOFFLineNumber[] lineNumbers = dcsh.getLineNumbers();
		if (shouldShowDebugLineNumbers(options) && lineNumbers != null) {
			for (DebugCOFFLineNumber lineNumber : lineNumbers) {
				if (monitor.isCancelled()) {
					return;
				}

				if (lineNumber.getLineNumber() == 0) {
					//TODO: lookup function name
				}
				else {
					addLineComment(
						program.getImageBase().add(Conv.intToLong(lineNumber.getVirtualAddress())),
						lineNumber.getLineNumber());
				}
			}
		}
	}

	protected boolean processDebugCoffSymbol(DebugCOFFSymbol symbol, NTHeader ntHeader,
			Map<SectionHeader, Address> sectionToAddress, Program program,
			TaskMonitor monitor) {

		if (symbol.getSectionNumber() == 0) {
			return true;
		}

		String sym = symbol.getName();
		if (sym == null || sym.length() == 0) {
			return true;
		}

		int val = symbol.getValue();
		if (val == 0) {
			return true;
		}

		if (symbol.getSectionNumber() == DebugCOFFSymbol.IMAGE_SYM_ABSOLUTE) {
			return true;
		}

		if (symbol.getSectionNumber() == DebugCOFFSymbol.IMAGE_SYM_DEBUG) {
			return true;
		}

		FileHeader fileHeader = ntHeader.getFileHeader();
		SectionHeader section = fileHeader.getSectionHeader(symbol.getSectionNumber() - 1);
		if (section == null) {
			return false;
		}

		Address address = null;
		PeSubsystem subsystem = PeSubsystem.parse(ntHeader.getOptionalHeader().getSubsystem());
		if (subsystem == PeSubsystem.IMAGE_SUBSYSTEM_NATIVE) {
			// We've observed that drivers add symbol values to the image base rather than the start
			// of their reported section.
			address = program.getImageBase();
		}
		else {
			address = sectionToAddress.get(section);
		}
		if (address == null) {
			return false;
		}

		address = address.add(Integer.toUnsignedLong(val));

		try {
			Symbol newSymbol =
				program.getSymbolTable().createLabel(address, sym, SourceType.IMPORTED);

			// Force non-section symbols to be primary.  We never want section symbols (.text,
			// .text$func_name) to be primary because we don't want to use them for function names
			// or demangling.
			if (!sym.equals(section.getName()) && !sym.startsWith(section.getName() + "$")) {
				newSymbol.setPrimary();
			}
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Error creating label named " + sym + " at address " + address + ": " +
				e.getMessage());
		}

		demangle(address, sym, program);

		DebugCOFFSymbolAux[] auxs = symbol.getAuxiliarySymbols();
		for (DebugCOFFSymbolAux aux : auxs) {
			if (monitor.isCancelled()) {
				break;
			}
			if (aux == null) {
				continue;
			}
			setComment(CodeUnit.PRE_COMMENT, address, aux.toString());
		}

		return true;
	}

	private void processDebugFixup(DebugFixup df) {
		if (df == null) {
			return;
		}

		//TODO: determine how to use fixup information
		//DebugFixupElement [] elements = df.getDebugFixupElements();
	}

	private void processDebugMisc(Program program, DebugMisc dm) {
		if (dm == null) {
			return;
		}

		String actualData = dm.getActualData();
		int datatype = dm.getDataType();

		DebugDirectory dd = dm.getDebugDirectory();

		if (dd.getAddressOfRawData() > 0) {
			Address address = program.getImageBase().add(dd.getAddressOfRawData());
			try {
				program.getListing().createData(address, new StringDataType(), actualData.length());
				program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, "Debug Misc");
				address = address.add(actualData.length());
				program.getListing().createData(address, new DWordDataType());
			}
			catch (CodeUnitInsertionException e) {
				// ignore
			}
		}

		Options proplist = program.getOptions(Program.PROGRAM_INFO);

		proplist.setString("Debug Misc", actualData);
		proplist.setString("Debug Misc Datatype", "0x" + Conv.toHexString(datatype));
	}

	private void addLineComment(Address addr, int line) {
		String cmt = addr + " -> " + "Line #" + line;
		setComment(CodeUnit.PRE_COMMENT, addr, cmt);
	}

	protected boolean hasComment(int type, Address address) {
		switch (type) {
			case CodeUnit.PLATE_COMMENT:
				return plateCommentMap.get(address) != null;
			case CodeUnit.PRE_COMMENT:
				return preCommentMap.get(address) != null;
			case CodeUnit.POST_COMMENT:
				return postCommentMap.get(address) != null;
			case CodeUnit.EOL_COMMENT:
				return eolCommentMap.get(address) != null;
		}
		return false;
	}

	protected void setComment(int type, Address address, String comment) {
		StringBuffer buffer = null;
		switch (type) {
			case CodeUnit.PLATE_COMMENT:
				buffer = plateCommentMap.get(address);
				if (buffer == null) {
					buffer = new StringBuffer();
					plateCommentMap.put(address, buffer);
				}
				break;
			case CodeUnit.PRE_COMMENT:
				buffer = preCommentMap.get(address);
				if (buffer == null) {
					buffer = new StringBuffer();
					preCommentMap.put(address, buffer);
				}
				break;
			case CodeUnit.POST_COMMENT:
				buffer = postCommentMap.get(address);
				if (buffer == null) {
					buffer = new StringBuffer();
					postCommentMap.put(address, buffer);
				}
				break;
			case CodeUnit.EOL_COMMENT:
				buffer = eolCommentMap.get(address);
				if (buffer == null) {
					buffer = new StringBuffer();
					eolCommentMap.put(address, buffer);
				}
				break;
		}
		if (buffer != null) {
			if (buffer.length() > 0) {
				buffer.append('\n');
			}
			buffer.append(comment);
		}
	}
}
