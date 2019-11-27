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
package ghidra.app.plugin.exceptionhandlers.gcc;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.plugin.exceptionhandlers.gcc.sections.*;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.ExceptionHandlerFrameException;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An analyzer for locating and marking up the GCC exception handling information.
 */
public class GccExceptionAnalyzer extends AbstractAnalyzer {

	public static final String NAME = "GCC Exception Handlers";
	public static final String DESCRIPTION =
		"Locates and annotates exception-handling infrastructure installed by the GCC compiler";

	protected static final String OPTION_NAME_CREATE_TRY_CATCH_COMMENTS =
		"Create Try Catch Comments";
	private static final String OPTION_DESCRIPTION_CREATE_TRY_CATCH_COMMENTS =
		"Selecting this check box causes the analyzer to create comments in the " +
			"disassembly listing for the try and catch code.";
	private static final boolean OPTION_DEFAULT_CREATE_TRY_CATCH_COMMENTS_ENABLED = true;
	private boolean createTryCatchCommentsEnabled =
		OPTION_DEFAULT_CREATE_TRY_CATCH_COMMENTS_ENABLED;

	private Set<Program> visitedPrograms = new HashSet<>();
	private AutoAnalysisManagerListener analysisListener =
		(manager) -> visitedPrograms.remove(manager.getProgram());

	/**
	 * Creates an analyzer for marking up the GCC exception handling information.
	 */
	public GccExceptionAnalyzer() {

		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after());
	}

	private MemoryBlock getBlock(Program program, String name) {
		return program.getMemory().getBlock(name);
	}

	private boolean hasBlock(Program program, String name) {
		return getBlock(program, name) != null;
	}

	private boolean hasBlockWithPrefix(Program program, String prefix) {

		for (MemoryBlock block : program.getMemory().getBlocks()) {

			if (block.getName().startsWith(prefix)) {
				return true;
			}

		}
		return false;
	}

	private boolean hasARMSection(Program program) {

		// ARM GCC exception handling support removed pending further review
		return false;

//		boolean hasArmExIdx = hasBlockWithPrefix(program, ARMExIdxSection.EX_IDX_BLOCK_NAME_PREFIX);
//		boolean hasArmExTab = hasBlockWithPrefix(program, ARMExTabSection.EX_TAB_BLOCK_NAME_PREFIX);
//
//		return hasArmExIdx || hasArmExTab;
	}

	@Override
	public boolean canAnalyze(Program program) {

		boolean isGcc =
			program.getCompilerSpec().getCompilerSpecID().getIdAsString().equalsIgnoreCase("gcc");

		boolean isDefault =
			program.getCompilerSpec().getCompilerSpecID().getIdAsString().equalsIgnoreCase(
				"default");

		if (!isGcc && !isDefault) {
			return false;
		}

		boolean hasEHFrameHeader =
			hasBlock(program, EhFrameHeaderSection.EH_FRAME_HEADER_BLOCK_NAME);

		boolean hasEHFrame = hasBlock(program, EhFrameSection.EH_FRAME_BLOCK_NAME);

		boolean hasDebugFrame =
			hasBlockWithPrefix(program, DebugFrameSection.DEBUG_FRAME_BLOCK_NAME);

		return hasEHFrame || hasEHFrameHeader || hasARMSection(program) || hasDebugFrame;
	}

	@Override
	public boolean added(Program program, AddressSetView addedLocationAddresses,
			TaskMonitor monitor, MessageLog log) throws CancelledException {

		if (visitedPrograms.contains(program)) {
			return true;
		}

		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		analysisManager.addListener(analysisListener);

		monitor.setMessage("Analyzing GCC exception-handling artifacts");
		monitor.setIndeterminate(true);
		monitor.setShowProgressValue(false);

		handleStandardSections(program, monitor, log);

		handleDebugFrameSection(program, monitor, log);

		// handleArmSections(program, monitor, log);

		visitedPrograms.add(program);
		monitor.setIndeterminate(false);
		monitor.setShowProgressValue(true);

		return true;
	}

	/*
	 * Parses the standard GCC exception handling support sections:
	 * 1) EHFrameHeader ('.eh_frame_hdr')
	 * 2) EHFrame ('.eh_frame') 
	 */
	private void handleStandardSections(Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		int fdeTableCount = analyzeEhFrameHeaderSection(program, monitor, log);
		// If the EHFrameHeader doesn't exist, the fdeTableCount will be 0.

		monitor.checkCanceled();

		try {
			/*
			 * If the .eh_frame section exists, build the structures
			 * contained within this program section.
			 */

			EhFrameSection ehframeSection = new EhFrameSection(monitor, program);
			List<RegionDescriptor> regions = ehframeSection.analyze(fdeTableCount);

			AddressSet ehProtected = new AddressSet();

			for (RegionDescriptor region : regions) {

				monitor.checkCanceled();
				ehProtected.add(region.getRange());

				LSDACallSiteTable callSiteTable = region.getCallSiteTable();
				if (callSiteTable != null) {

					// Process this table's call site records.
					for (LSDACallSiteRecord cs : callSiteTable.getCallSiteRecords()) {
						monitor.checkCanceled();
						processCallSiteRecord(program, ehProtected, region, cs);
					}
				}
			}

		}
		catch (MemoryAccessException | ExceptionHandlerFrameException e) {
			log.appendMsg("Error analyzing GCC exception tables");
			log.appendException(e);
		}
	}

	private void processCallSiteRecord(Program program, AddressSet ehProtected,
			RegionDescriptor region, LSDACallSiteRecord cs) {
		AddressRange callSite = cs.getCallSite();
		ehProtected.add(callSite);

		Address csAddr = cs.getCallSite().getMinAddress();
		long lpOffset = cs.getLandingPadOffset();

		if (lpOffset != 0) {

			Address lpAddr = cs.getLandingPad();

			ehProtected.add(lpAddr);

			List<TypeInfo> typeInfos = getTypeInfos(region, cs);

			disassembleIfNeeded(program, csAddr);
			if (createTryCatchCommentsEnabled) {
				markStartOfTry(program, callSite, lpAddr);
				markEndOfTry(program, callSite);
			}

			disassembleIfNeeded(program, lpAddr);
			if (createTryCatchCommentsEnabled) {
				markStartOfCatch(program, csAddr, lpAddr, typeInfos);
				markEndOfCatch(program, callSite, lpAddr);
			}

		}
	}

	private List<TypeInfo> getTypeInfos(RegionDescriptor region, LSDACallSiteRecord cs) {

		List<TypeInfo> typeInfos = new ArrayList<>();

		LSDAActionTable actionTable = region.getActionTable(); // This can be null.
		LSDATypeTable typeTable = region.getTypeTable(); // This can be null.
		if (actionTable == null || typeTable == null) {
			return typeInfos; // No action records.
		}

		int actionOffset = cs.getActionOffset();
		// If we have a valid offset then get that action record.
		LSDAActionRecord action = actionTable.getActionRecordAtOffset(actionOffset);

		while (action != null) {

			int actionFilter = action.getActionTypeFilter();
			Address typeInfoAddress = typeTable.getTypeInfoAddress(actionFilter);
			TypeInfo typeInfo = new TypeInfo(typeInfoAddress, actionFilter);
			typeInfos.add(typeInfo);

			action = action.getNextAction();
		}

		return typeInfos;
	}

	private boolean shouldDisassemble() {
		return true;
	}

	private boolean disassembleIfNeeded(Program program, Address address) {
		if (!shouldDisassemble()) {
			return false;
		}
		Listing listing = program.getListing();
		Instruction inst = listing.getInstructionAt(address);
		// location should be protected from clearing
		AutoAnalysisManager.getAnalysisManager(program).setProtectedLocation(address);
		if (inst == null) {
			DisassembleCommand cmd = new DisassembleCommand(address, null, true);
			if (!cmd.applyTo(program) || cmd.getDisassembledAddressSet().isEmpty()) {
				String message = "Failed to disassemble at " + address;
				Msg.error(this, message);
				return false;
			}
			return true;
		}
		return false; // already disassembled
	}

	private void markStartOfTry(Program program, AddressRange callSite, Address lpAddr) {
		Address csMinAddr = callSite.getMinAddress();
		Address csMaxAddr = callSite.getMaxAddress();
		String startTryComment = "try { // try from " + csMinAddr + " to " + csMaxAddr +
			" has its CatchHandler @ " + lpAddr;
		String existingComment = program.getListing().getComment(CodeUnit.PRE_COMMENT, csMinAddr);
		if (existingComment == null || !existingComment.contains(startTryComment)) {
			String mergedComment = StringUtilities.mergeStrings(existingComment, startTryComment);
			SetCommentCmd setCommentCmd =
				new SetCommentCmd(csMinAddr, CodeUnit.PRE_COMMENT, mergedComment);
			setCommentCmd.applyTo(program);
		}
	}

	private void markEndOfTry(Program program, AddressRange callSite) {
		Address csMinAddr = callSite.getMinAddress();
		Address csMaxAddr = callSite.getMaxAddress();
		CodeUnit csMaxCodeUnit = program.getListing().getCodeUnitContaining(csMaxAddr);
		if (csMaxCodeUnit != null) {
			Address commentAddr = csMaxCodeUnit.getMinAddress();
			String endTryComment = "} // end try from " + csMinAddr + " to " + csMaxAddr;
			String existingComment =
				program.getListing().getComment(CodeUnit.POST_COMMENT, commentAddr);
			if (existingComment == null || !existingComment.contains(endTryComment)) {
				String mergedComment = StringUtilities.mergeStrings(existingComment, endTryComment);
				SetCommentCmd setCommentCmd =
					new SetCommentCmd(commentAddr, CodeUnit.POST_COMMENT, mergedComment);
				setCommentCmd.applyTo(program);
			}
		}
	}

	private void markStartOfCatch(Program program, Address csAddr, Address lpAddr,
			List<TypeInfo> typeInfos) {

		String typeString =
			typeInfos.stream().map(a -> getCatchParamInfo(a)).collect(Collectors.joining(", "));
		String startCatchComment =
			"catch(" + typeString + ") { ... } // from try @ " + csAddr + " with catch @ " + lpAddr;
		String existingComment = program.getListing().getComment(CodeUnit.PRE_COMMENT, lpAddr);
		if (existingComment == null || !existingComment.contains(startCatchComment)) {
			String mergedComment = StringUtilities.mergeStrings(existingComment, startCatchComment);
			SetCommentCmd setCommentCmd =
				new SetCommentCmd(lpAddr, CodeUnit.PRE_COMMENT, mergedComment);
			setCommentCmd.applyTo(program);
		}
	}

	private String getCatchParamInfo(TypeInfo a) {
		int actionFilter = a.getActionFilter();
		Address typeInfoAddress = a.getTypeInfoAddress();
		if (actionFilter == 0 || typeInfoAddress == Address.NO_ADDRESS) {
			return "";
		}
		return "type#" + actionFilter + " @ " + typeInfoAddress;
	}

	private void markEndOfCatch(Program program, AddressRange callSite, Address lpAddr) {
		// TODO  Need to figure out way to indicate this that won't get wiped out by other analysis.
//	*** The following is commented out until we figure out how to determine end of catch. ***
//		// TODO If we can determine the length of the catch handler we could mark its end too.
//		Address lpMaxAddr = ?;
//		String endCatchComment = "} // end catchHandler()";
//		String existingComment = program.getListing().getComment(CodeUnit.POST_COMMENT, lpMaxAddr);
//		if (existingComment == null || !existingComment.contains(endCatchComment)) {
//			String mergedComment =
//				StringUtilities.mergeStrings(existingComment, endCatchComment);
//			SetCommentCmd setCommentCmd =
//				new SetCommentCmd(lpMaxAddr, CodeUnit.POST_COMMENT, endCatchComment);
//			setCommentCmd.applyTo(program);
//		}
	}

	private int analyzeEhFrameHeaderSection(Program program, TaskMonitor monitor, MessageLog log) {

		try {
			EhFrameHeaderSection ehframehdrSection = new EhFrameHeaderSection(program);
			return ehframehdrSection.analyze(monitor);
		}
		catch (AddressOutOfBoundsException | MemoryAccessException
				| ExceptionHandlerFrameException e) {
			log.appendMsg("Error analyzing GCC EH Frame Header exception table");
			log.appendException(e);
		}
		return 0;
	}

//	private void handleArmSections(Program program, TaskMonitor monitor, MessageLog log)
//			throws CancelledException {
//
//		try {
//			ARMExIdxSection exIdxSection = new ARMExIdxSection(program);
//			exIdxSection.analyze(monitor);
//		}
//		catch (MemoryAccessException | ExceptionHandlerFrameException e) {
//			log.appendMsg("Error analyzing GCC ARM exception tables");
//			log.appendException(e);
//		}
//
//		try {
//			ARMExTabSection exTabSection = new ARMExTabSection(program);
//			exTabSection.analyze(monitor);
//		}
//		catch (MemoryAccessException e) {
//			log.appendMsg("Error analyzing GCC ARM exception tables");
//			log.appendException(e);
//		}
//	}

	private void handleDebugFrameSection(Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		try {
			DebugFrameSection debugFrameSection = new DebugFrameSection(monitor, program);
			debugFrameSection.analyze();
		}
		catch (MemoryAccessException | ExceptionHandlerFrameException e) {
			log.appendMsg("Error analyzing GCC DebugFrame exception tables");
			log.appendException(e);
		}
	}

	/**
	 * A TypeInfo associates the address of a type information record with the filter value that 
	 * is used to handle a catch action for that type. 
	 */
	private class TypeInfo {
		private Address typeInfoAddress;
		private int actionFilter;

		public TypeInfo(Address typeInfoAddress, int actionFilter) {
			this.typeInfoAddress = typeInfoAddress;
			this.actionFilter = actionFilter;
		}

		public Address getTypeInfoAddress() {
			return typeInfoAddress;
		}

		public int getActionFilter() {
			return actionFilter;
		}
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_CREATE_TRY_CATCH_COMMENTS, createTryCatchCommentsEnabled,
			null, OPTION_DESCRIPTION_CREATE_TRY_CATCH_COMMENTS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		createTryCatchCommentsEnabled = options.getBoolean(OPTION_NAME_CREATE_TRY_CATCH_COMMENTS,
			createTryCatchCommentsEnabled);
	}

}
