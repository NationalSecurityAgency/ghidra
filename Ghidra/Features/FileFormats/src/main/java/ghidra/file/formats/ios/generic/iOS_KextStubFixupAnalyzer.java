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
package ghidra.file.formats.ios.generic;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class iOS_KextStubFixupAnalyzer extends FileFormatAnalyzer {

	@Override
	public String getName() {
		return "iOS Kext STUB Section Fixup";
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.BYTE_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;//isKext( program );
	}

	@Override
	public String getDescription() {
		return "Attempts to locate symbol names for addresses in the STUB section of iOS kext files by scanning" +
			" all kext files in the current project. The entire iOS kernel should be loaded into the project for this" +
			" to operate optimally.";
	}

	@Override
	public AnalysisPriority getPriority() {
		return AnalysisPriority.LOW_PRIORITY;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return false;//isKext( program );
	}

	@Override
	public boolean isPrototype() {
		return true;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {

		//attempt to get the program manager service
		//we can keep working without it, but the analysis will run much slower
		ProgramManager programManager = null;
		AutoAnalysisManager autoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program);
		if (autoAnalysisManager != null) {
			PluginTool tool = autoAnalysisManager.getAnalysisTool();
			if (tool != null) {
				programManager = tool.getService(ProgramManager.class);
			}
		}

		Listing listing = program.getListing();
		SymbolTable symbolTable = program.getSymbolTable();
		Memory memory = program.getMemory();
		ReferenceManager referenceManager = program.getReferenceManager();
		ExternalManager externalManager = program.getExternalManager();

		MemoryBlock stubBlock = memory.getBlock("__stub");
		if (stubBlock == null) {
			stubBlock = memory.getBlock("__stubs");
		}
		if (stubBlock == null) {
			return true;
		}
		disassembleStubSection(program, stubBlock, monitor);
		Namespace stubNameSpace = getOrCreateNameSpace(program, stubBlock);

		MemoryBlock destinationBlock = memory.getBlock("__nl_symbol_ptr");
		if (destinationBlock == null) {
			destinationBlock = memory.getBlock("__got");
		}
		if (destinationBlock == null) {
			return true;
		}
		markupNonLazySymbolPointerSection(program, destinationBlock, monitor);
		Namespace nlSymbolPtrNameSpace = getOrCreateNameSpace(program, destinationBlock);

		DataIterator dataIterator =
			program.getListing().getData(toAddressSet(destinationBlock), true);
		while (dataIterator.hasNext()) {

			if (monitor.isCancelled()) {
				break;
			}

			Data data = dataIterator.next();

			if (data.getMinAddress().compareTo(destinationBlock.getEnd()) > 0) {
				break;
			}

			monitor.setMessage("Fixing STUB section at " + data.getMinAddress());

			Object value = data.getValue();

			if (!(value instanceof Address)) {
				continue;
			}

			Address destinationAddress = (Address) value;

			if (memory.contains(destinationAddress)) {
				continue;
			}

			if ((destinationAddress.getOffset() % 2) != 0) {
				destinationAddress =
					destinationAddress.getNewAddress(destinationAddress.getOffset() - 1);
			}

			DestinationProgramInfo destinationProgramInfo =
				findDestinationProgram(program, programManager, destinationAddress, monitor);

			if (destinationProgramInfo == null) {
				continue;
			}

			createSymbolInNonLazySymbolPointerSection(symbolTable, nlSymbolPtrNameSpace, data,
				destinationProgramInfo);

			createExternalReferenceInNonLazySymbolPointerSection(referenceManager, externalManager,
				data, destinationAddress, destinationProgramInfo);

			createSymbolInStubSection(listing, symbolTable, referenceManager, stubNameSpace, data,
				destinationProgramInfo, monitor);
		}

		return true;
	}

	private void createSymbolInStubSection(Listing listing, SymbolTable symbolTable,
			ReferenceManager referenceManager, Namespace stubNameSpace, Data data,
			DestinationProgramInfo destinationProgramInfo, TaskMonitor monitor) {

		// follow back reference to rename function in the "__stub" section

		ReferenceIterator referencesTo = referenceManager.getReferencesTo(data.getMinAddress());
		while (referencesTo.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Reference reference = referencesTo.next();
			Function function = listing.getFunctionContaining(reference.getFromAddress());
			try {
				symbolTable.createLabel(function.getEntryPoint(), destinationProgramInfo.symbolName,
					stubNameSpace, SourceType.ANALYSIS);
			}
			catch (Exception e) {
			}
		}
	}

	private void createExternalReferenceInNonLazySymbolPointerSection(
			ReferenceManager referenceManager, ExternalManager externalManager, Data data,
			Address destinationAddress, DestinationProgramInfo destinationProgramInfo) {

		// lay down external reference on the data in the "__nl_symbol_ptr" section
		try {
			referenceManager.addExternalReference(data.getMinAddress(),
				destinationProgramInfo.programName, destinationProgramInfo.symbolName,
				destinationAddress, SourceType.ANALYSIS, 0, RefType.DATA);

			externalManager.setExternalPath(destinationProgramInfo.programName,
				destinationProgramInfo.programPath, false);
		}
		catch (Exception e) {
		}
	}

	private void createSymbolInNonLazySymbolPointerSection(SymbolTable symbolTable,
			Namespace nlSymbolPtrNameSpace, Data data,
			DestinationProgramInfo destinationProgramInfo) {
		// create symbol in the "__nl_symbol_ptr" section
		try {
			symbolTable.createLabel(data.getMinAddress(), destinationProgramInfo.symbolName,
				nlSymbolPtrNameSpace, SourceType.ANALYSIS);
		}
		catch (Exception e) {
		}
	}

	private void markupNonLazySymbolPointerSection(Program program, MemoryBlock block,
			TaskMonitor monitor) {
		ReferenceManager referenceManager = program.getReferenceManager();
		Listing listing = program.getListing();
		listing.clearCodeUnits(block.getStart(), block.getEnd(), false);
		Address address = block.getStart();
		while (!monitor.isCancelled()) {
			if (address.compareTo(block.getEnd()) > 0) {
				break;
			}
			int length;
			try {
				Data data = listing.createData(address, new PointerDataType());
				Reference[] references = data.getReferencesFrom();
				for (Reference reference : references) {
					if (monitor.isCancelled()) {
						break;
					}
					referenceManager.delete(reference);
				}
				length = data.getLength();
			}
			catch (Exception e) {
				return;
			}
			address = address.add(length);
		}
	}

	private void disassembleStubSection(Program program, MemoryBlock block, TaskMonitor monitor) {
	}

	private Namespace getOrCreateNameSpace(Program program, MemoryBlock block)
			throws DuplicateNameException, InvalidInputException {

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace parent = program.getGlobalNamespace();
		Namespace namespace = symbolTable.getNamespace(block.getName(), parent);
		if (namespace != null) {
			return namespace;
		}
		return symbolTable.createNameSpace(parent, block.getName(), SourceType.ANALYSIS);
	}

	private AddressSet toAddressSet(MemoryBlock block) {
		return new AddressSet(block.getStart(), block.getEnd());
	}

	private DestinationProgramInfo findDestinationProgram(Program sourceProgram,
			ProgramManager programManager, Address destinationAddress, TaskMonitor monitor) {

		if (programManager != null) {
			Program alreadyOpenProgram = programManager.getProgram(destinationAddress);
			if (alreadyOpenProgram != null) {
				if (alreadyOpenProgram.getMemory().contains(destinationAddress)) {
					SymbolTable symbolTable = alreadyOpenProgram.getSymbolTable();
					Symbol symbol = symbolTable.getPrimarySymbol(destinationAddress);
					return new DestinationProgramInfo(alreadyOpenProgram.getName(),
						alreadyOpenProgram.getDomainFile().getPathname(),
						symbol == null ? null : symbol.getName());
				}
			}
		}
		String[] parts = sourceProgram.getDomainFile().getPathname().split("/");
		String firmwareVersion = parts[1];
		Project project = AppInfo.getActiveProject();
		ProjectData projectData = project.getProjectData();
		DomainFolder rootFolder = projectData.getRootFolder();
		DomainFolder folder = rootFolder.getFolder(firmwareVersion);
		if (folder == null) {
			return null;
		}
		return recurseFolder(folder, destinationAddress, programManager, monitor);
	}

	private DestinationProgramInfo recurseFolder(DomainFolder folder, Address destinationAddress,
			ProgramManager programManager, TaskMonitor monitor) {
		DomainFolder[] folders = folder.getFolders();
		for (DomainFolder child : folders) {
			if (monitor.isCancelled()) {
				break;
			}
			DestinationProgramInfo info =
				recurseFolder(child, destinationAddress, programManager, monitor);
			if (info != null) {
				return info;
			}
		}
		DomainFile[] files = folder.getFiles();
		for (DomainFile file : files) {
			if (monitor.isCancelled()) {
				break;
			}
			DomainObject domainObject = null;
			try {
				domainObject = file.getDomainObject(this, true /* upgrade */,
					false /* do not recover */, monitor);
				if (domainObject instanceof Program) {
					Program program = (Program) domainObject;
					if (program.getMemory().contains(destinationAddress)) {
						if (programManager != null) {
							programManager.openProgram(program, ProgramManager.OPEN_VISIBLE);//once program is located, open it, so lookup is faster next time!
						}
						SymbolTable symbolTable = program.getSymbolTable();
						Symbol symbol = symbolTable.getPrimarySymbol(destinationAddress);
						String symbolName = symbol == null ? null : symbol.getName();
						return new DestinationProgramInfo(program.getName(), file.getPathname(),
							symbolName);
					}
				}
			}
			catch (Exception e) {
				Msg.warn(this, e);
			}
			finally {
				if (domainObject != null) {
					domainObject.release(this);
				}
			}
		}
		return null;
	}

	boolean isKext(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		if (processor.equals(Processor.findOrPossiblyCreateProcessor("ARM")) ||
			processor.equals(Processor.findOrPossiblyCreateProcessor("AARCH64"))) {
			return program.getName().toLowerCase().endsWith(".kext");
		}
		return false;
	}

	class DestinationProgramInfo {
		String programName;
		String programPath;
		String symbolName;

		DestinationProgramInfo(String programName, String programPath, String symbolName) {
			this.programName = programName;
			this.programPath = programPath;
			this.symbolName = symbolName;
		}
	}
}
