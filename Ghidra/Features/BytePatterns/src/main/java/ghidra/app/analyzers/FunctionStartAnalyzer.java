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
package ghidra.app.analyzers;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

import generic.jar.ResourceFile;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.util.Msg;
import ghidra.util.bytesearch.*;
import ghidra.util.constraint.ProgramDecisionTree;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class FunctionStartAnalyzer extends AbstractAnalyzer implements PatternFactory {
	private static final String FUNCTION_START_SEARCH = "Function Start Search";
	protected static final String NAME = FUNCTION_START_SEARCH;
	private static final String DESCRIPTION =
		"Search for architecture specific byte patterns: typically starts of functions";
	private static final String PRE_FUNCTION_MATCH_PROPERTY_NAME = "PreFunctionMatch";
	private final static String OPTION_NAME_DATABLOCKS = "Search Data Blocks";
	private static final String OPTION_DESCRIPTION_DATABLOCKS =
		"Search for byte patterns in blocks that are not executable";
	private final static boolean OPTION_DEFAULT_DATABLOCKS = false;
	private final static String OPTION_NAME_BOOKMARKS = "Bookmark Functions";
	private final static String OPTION_DESCRIPTION_BOOKMARKS =
		"Place a bookmark at functions that were discovered by a pattern";
	private final static boolean OPTION_DEFAULT_BOOKMARKS = false;

	private static ProgramDecisionTree patternDecisitionTree;
	// always need to initialize the root.
	SequenceSearchState rootState = null;
	SequenceSearchState explicitState = null;  //for use during dynamic function start pattern discovery

	private boolean executableBlocksOnly = true; // true if we only analyze executable blocks

	private boolean setbookmark = OPTION_DEFAULT_BOOKMARKS; // true if book mark should be set at pattern hits

	// These flags are how we know to run a Data or Code analyzer
	protected boolean hasDataConstraints = false; // true if any pattern must follow new data
	protected boolean hasCodeConstraints = false; // true if any pattern must follow code
	protected boolean hasFunctionStartConstraints = false; // true if any pattern must start at a function

	// property map breadcrumbs to cut down re-pattern search
	protected AddressSetPropertyMap potentialMatchAddressSetPropertyMap;

	// This is running state when doing analysis.
	//   These should go away after analysis, and really should be passed around...
	private AddressSet funcResult = null; // Discovered function starts
	private AddressSet potentialFuncResult = null; // Discovered potential Func Start
	private AddressSet disassemResult = null; // Discovered code that needs disassembly locations
	private AddressSet codeLocations = null;  // Discovered good code locations
	protected AddressSet postreqFailedResult = null; // Discovered pattern, but a post req failed (not following a defined thing)
	protected ArrayList<RegisterValue> contextValueList = null;

	private static ProgramDecisionTree getPatternDecisionTree() {
		if (patternDecisitionTree == null) {
			patternDecisitionTree = Patterns.getPatternDecisionTree();
		}
		return patternDecisitionTree;
	}

	public FunctionStartAnalyzer() {
		this(NAME, AnalyzerType.BYTE_ANALYZER);
	}

	public FunctionStartAnalyzer(String name, AnalyzerType analyzerType) {
		super(name, DESCRIPTION, analyzerType);
		setPriority(AnalysisPriority.CODE_ANALYSIS.after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	/**
	 * Sets the {@link SequenceSearchState}. Use this method when you've created a 
	 * {@link SequenceSearchState} that you want to apply to the program. If you don't set
	 * the state explicitly, Ghidra will create one from the appropriate pattern file in
	 * {@link SequenceSearchState#initialize}
	 * @param explicit
	 */
	public void setExplicitState(SequenceSearchState explicit) {
		explicitState = explicit;
	}

	/**
	 * Clears the explict state.
	 */
	public void clearExplicitState() {
		explicitState = null;
	}

	/**
	 * apply any latent context at the location
	 *
	 * @param program
	 * @param addr
	 */
	private void setCurrentContext(Program program, Address addr) {
		if (contextValueList == null) {
			return;
		}
		ProgramContext programContext = program.getProgramContext();

		Iterator<RegisterValue> iterator = contextValueList.iterator();
		while (iterator.hasNext()) {
			RegisterValue contextValue = iterator.next();

			try {
				programContext.setRegisterValue(addr, addr, contextValue);
			}
			catch (ContextChangeException e) {
				// context conflicts cause problems, let already layed down context win.
			}
		}

		// context applied at location, throw away
		contextValueList = null;
	}

	private void setDisassemblerContext(Program program, DisassemblerContext pcont) {
		if (contextValueList == null) {
			return;
		}
		Iterator<RegisterValue> iterator = contextValueList.iterator();
		while (iterator.hasNext()) {
			RegisterValue contextValue = iterator.next();

			try {
				pcont.setRegisterValue(contextValue);
			}
			catch (ContextChangeException e) {
				// context conflicts cause problems, let already layed down context win.
			}
		}
	}

	public class CodeBoundaryAction implements MatchAction {

		@Override
		public void apply(Program program, Address addr, Match match) {
			Listing listing = program.getListing();
			CodeUnit cu = listing.getCodeUnitContaining(addr);
			if (cu != null) {
				if (cu instanceof Data) {
					if (!((Data) cu).isDefined()) { // Undefined data
						setCurrentContext(program, addr);
						disassemResult.add(addr); // Schedule for disassembly
						codeLocations.add(addr);
					}
				}
				else {
					codeLocations.add(addr);
				}
			}
		}

		@Override
		public void restoreXml(XmlPullParser parser) {
			parser.start("codeboundary");
			parser.end();
		}

	}

	public class FunctionStartAction implements MatchAction {

		private String afterName = null;
		private int validcode = 0; // -1 means in a valid subroutine
		private String label = null;
		private boolean isThunk = false;  // true if this function should be turned into a thunk
		private boolean noreturn = false; // true to set function non-returning
		boolean validFunction = false; // must be defined at a function

		@Override
		public void apply(Program program, Address addr, Match match) {
			if (!checkPreRequisites(program, addr)) {
				return;
			}

			applyActionToSet(program, addr, funcResult, match);
		}

		protected boolean checkPreRequisites(Program program, Address addr) {
			/**
			 * If the match's mark point occurs in undefined data, schedule disassembly
			 * and a function start at that address. If the match's mark point occurs at an instruction, but that
			 * instruction isn't in a function body, schedule a function start at that address
			 */
			if (validFunction) {
				Function func = program.getFunctionManager().getFunctionAt(addr);
				if (func == null) {
					postreqFailedResult.add(addr);
					// Drop a property breadcrumb to make sure only those functions that could match are checked.
					potentialMatchAddressSetPropertyMap.add(addr, addr);
					return false;
				}
			}

			if (!checkAfterName(program, addr)) {
				postreqFailedResult.add(addr);
				return false;
			}

			// do we require some number of valid instructions
			if (validcode != 0) {
				PseudoDisassembler pseudoDisassembler = new PseudoDisassembler(program);
				PseudoDisassemblerContext pcont =
					new PseudoDisassemblerContext(program.getProgramContext());
				setDisassemblerContext(program, pcont);
				boolean isvalid = false;
				if (validcode == -1) {
					isvalid = pseudoDisassembler.checkValidSubroutine(addr, pcont, true, true);
				}
				else {
					pseudoDisassembler.setMaxInstructions(validcode);
					isvalid = pseudoDisassembler.checkValidSubroutine(addr, pcont, true, false);
				}
				if (!isvalid) {
					return false;
				}
			}

			return true;
		}

		protected void applyActionToSet(Program program, Address addr, AddressSet resultSet,
				Match match) {

			if ((addr.getOffset() % program.getLanguage().getInstructionAlignment()) != 0) {
				return; // addr is not properly aligned
			}

			Listing listing = program.getListing();
			CodeUnit cu = listing.getCodeUnitContaining(addr);
			Function func = listing.getFunctionContaining(addr);

			if (cu != null) {
				if (cu instanceof Data) {
					if (!((Data) cu).isDefined()) { // Undefined data
						setCurrentContext(program, addr);
						disassemResult.add(addr); // Schedule for disassembly
						codeLocations.add(addr);
						resultSet.add(addr); // Schedule for a function start
						bookmarkAction(program, addr, match);
					}
				}
				else { // An instruction
					if (func == null) { // Instruction but not in a function body
						// do a little more checking, Could addr already be in a function, or part of other code flow?
						if (!checkAlreadyInFunctionAbove(program, addr)) {
							resultSet.add(addr); // Schedule for a function start
							bookmarkAction(program, addr, match);
						}
					}
					else {
						// Presumably this is already marked as a function start so we don't have to do anything.
						// We could check that this is in fact the function entry point and if not, set a bookmark
					}
					codeLocations.add(addr);
				}
			}

			// make the function non-returning
			if (func != null && noreturn) {
				func.setNoReturn(true);
			}

			if (func != null && isThunk && !func.isThunk()) {
				CreateThunkFunctionCmd createThunkFunctionCmd =
					new CreateThunkFunctionCmd(addr, false);
				createThunkFunctionCmd.applyTo(program);
			}

			// pattern wants a name here, make it
			if (label != null) {
				String labelStr = label;

				if (setFunctionLabel(program, addr, labelStr) && func != null) {
					// kick analysis manager since by naming it, we may have changed the nature of a function
					AutoAnalysisManager analysisManager =
						AutoAnalysisManager.getAnalysisManager(program);
					analysisManager.functionDefined(new AddressSet(addr));
				}
			}
		}

		private boolean setFunctionLabel(Program program, Address addr, String labelStr) {
			boolean createdSym = false;

			SymbolTable symTable = program.getSymbolTable();
			Symbol sym = null;
			try {
				// figure out if we've done this before.
				Symbol[] symbols = symTable.getSymbols(addr);
				for (Symbol symbol : symbols) {
					if (symbol.getName().contains(labelStr)) {
						return false;
					}
				}
				sym = symTable.createLabel(addr, labelStr, null, SourceType.ANALYSIS);
				createdSym = true;
			}
			catch (InvalidInputException e) {
				// should not happen, unless there are bad characters in the name
			}
			if (sym != null) {
				sym.setPrimary();
			}
			return createdSym;
		}

		/**
		 * Check that this pattern occurs after something defined
		 * TODO: this would probably be better in a sub-pattern
		 */
		private boolean checkAfterName(Program program, Address addr) {
			if (afterName != null) {
				Address addrToCheck = addr.previous();

				// if pattern found at first address in contiguous defined address range in program
				//   allow after check to pass
				if (addrToCheck == null || !program.getMemory().contains(addrToCheck)) {
					// the address previous address is not in memory, so addr must be at the start of a block
					return true;
				}
				// or this is the start of a defined memory block
				MemoryBlock block = program.getMemory().getBlock(addr);
				if (block.getStart().equals(addr)) {
					// address is start of memory block so can't come after anything, must be OK
					return true;
				}

				String name = afterName;

				// if this place is already in a function, we shouldn't start one
				if (name.startsWith("func")) {
					Function funcAbove = getFunctionAbove(program, addr);
					if (funcAbove == null) {
						return false;
					}
					if (checkAlreadyInFunctionAbove(program, addr, funcAbove)) {
						return false;
					}
				}
				else if (name.startsWith("inst")) {
					// make sure there is an end of function at location to check
					Instruction instr = program.getListing().getInstructionContaining(addrToCheck);
					if (instr == null) {
						return false;
					}
				}
				else if (name.startsWith("data")) {
					// make sure there is defined data at location to check
					Data data = program.getListing().getDefinedDataContaining(addrToCheck);
					if (data == null) {
						return false;
					}
				}
				else if (name.startsWith("def")) {
					// make sure there is something at location to check
					Instruction instr = program.getListing().getInstructionContaining(addrToCheck);
					if (instr != null) {
						if (checkAlreadyInFunctionAbove(program, addr)) {
							return false;
						}
						return true;
					}
					Data data = program.getListing().getDefinedDataContaining(addrToCheck);
					if (data != null) {
						return true;
					}
					return false;
				}
			}
			return true;
		}

		/*
		 * Check if address if addr is already part of a function just preceding this address.
		 * If the address is part of another function that is different than the function right
		 * above, then the pattern should be applied, because it is most likely a unique function
		 * that is being used by another function as a shared return.
		 */
		private boolean checkAlreadyInFunctionAbove(Program program, Address addr) {
			Function funcAbove = getFunctionAbove(program, addr);
			return checkAlreadyInFunctionAbove(program, addr, funcAbove);
		}
		
		/*
		 * Check if in a function above
		 * return true if already in function above, false otherwise even if in another function
		 */
		private boolean checkAlreadyInFunctionAbove(Program program, Address addr, Function funcAbove) {
			// if no funcAbove, make sure an instruction, doesn't fall into this one.
			Address addrBefore = addr.previous();
			if (addrBefore == null) {
				return false;
			}
			if (funcAbove != null) {
				// check if in function right above
				Function myfunc = program.getFunctionManager().getFunctionContaining(addr);
				if (myfunc != null && myfunc.getEntryPoint().equals(funcAbove.getEntryPoint())) {
					return true;
				}
				// I could be in a different function, just not one above
				return false;
			}

			// no function above, but check for references, that would make this a function
			// or references that would imply it is part of another function.
			Instruction instr = program.getListing().getInstructionContaining(addrBefore);
			if (instr != null && addr.equals(instr.getFallThrough())) {
				return true;
			}
			// check for references to this function, address
			ReferenceIterator referencesTo =
				program.getReferenceManager().getReferencesTo(addr);
			for (Reference reference : referencesTo) {
				// someone flows to or reads/writes this location, shouldn't be a start
				RefType referenceType = reference.getReferenceType();
				if (referenceType.isData() &&
					!(referenceType.isRead() || referenceType.isWrite())) {
					continue;
				}
				// any other reference to here is bad, since a function or other flow should
				//   have created the location
				return true;
			}

			return false;
		}
		
		/**
		 * Get an existing function right above the addr.
		 * @param program program to check
		 * @param addr address to check
		 * @return true if there is an existing function above addr
		 */				
		private Function getFunctionAbove(Program program, Address addr) {
			// make sure there is an end of function before this one, and addr is not in the function
			Function func = null;
			Address addrBefore = addr.previous();
			if (addrBefore == null) {
				return null;
			}
			func = program.getFunctionManager().getFunctionContaining(addrBefore);
			return func;
		}

		void bookmarkAction(Program program, Address addr, Match match) {
			if (setbookmark) {
				BookmarkManager bookmarkManager = program.getBookmarkManager();
				bookmarkManager.setBookmark(addr, BookmarkType.ANALYSIS, getName(),
					"Match pattern " + match.getSequenceIndex());
			}
		}

		@Override
		public void restoreXml(XmlPullParser parser) {
			XmlElement el = parser.start("funcstart");
			restoreXmlAttributes(el);
			parser.end();
		}

		protected void restoreXmlAttributes(XmlElement el) {
			if (el.hasAttribute("after")) {
				afterName = el.getAttribute("after");
				if (afterName.startsWith("func")) {
					hasCodeConstraints = true;
				}
				else if (afterName.startsWith("inst")) {
					hasCodeConstraints = true;
				}
				else if (afterName.startsWith("data")) {
					hasDataConstraints = true;
				}
				else if (afterName.startsWith("def")) {
					hasCodeConstraints = hasDataConstraints = true;
				}
				else {
					Msg.error(this,
						"funcstart pattern attribute 'after' must be one of 'function', 'instruction', 'data', 'defined'");
				}
			}
			if (el.hasAttribute("validcode")) {
				validcode = 8;
				String validcodeStr = el.getAttribute("validcode");
				if (validcodeStr.equals("0") || validcodeStr.equals("false")) {
					validcode = 0;
				}
				else if (validcodeStr.equalsIgnoreCase("true") ||
					validcodeStr.equalsIgnoreCase("subroutine")) { // must be a valid subroutine
					validcode = -1;
				}
				else if (validcodeStr.equalsIgnoreCase("function")) { // must be at a defined subroutine
					validFunction = true;
					hasFunctionStartConstraints = true;
				}
				else { // must have <N> valid instruction run
					validcode = Integer.parseInt(validcodeStr);
				}
			}
			if (el.hasAttribute("label")) {
				String name = el.getAttribute("label");
				label = name;
			}
			if (el.hasAttribute("thunk")) {
				isThunk = true;
			}
			if (el.hasAttribute("noreturn")) {
				noreturn = true;
			}
		}

	}

	public class PossibleFunctionStartAction extends FunctionStartAction {
		@Override
		public void apply(Program program, Address addr, Match match) {
			if (!checkPreRequisites(program, addr)) {
				return;
			}
			applyActionToSet(program, addr, potentialFuncResult, match);
		}

		@Override
		void bookmarkAction(Program program, Address addr, Match match) {
			if (setbookmark) {
				BookmarkManager bookmarkManager = program.getBookmarkManager();
				bookmarkManager.setBookmark(addr, BookmarkType.ANALYSIS, "Possible " + getName(),
					"Match pattern " + match.getSequenceIndex());
			}
		}

		@Override
		public void restoreXml(XmlPullParser parser) {
			XmlElement el = parser.start("possiblefuncstart");
			restoreXmlAttributes(el);
			parser.end();
		}
	}

	public class ContextAction implements MatchAction {
		private String contextRegName = null; // Name of the context register to be set
		private BigInteger value = null;

		public ContextAction() {

		}

		public ContextAction(String register, BigInteger value) {
			this.contextRegName = register;
			this.value = value;
		}

		@Override
		public void apply(Program program, Address addr, Match match) {
			Listing listing = program.getListing();
			CodeUnit cu = listing.getCodeUnitContaining(addr);
			if (cu != null) {
				if (cu instanceof Data) {
					if (((Data) cu).isDefined()) {
						return;
					}
				}
				else {
					return;
				}
			}
			if (contextValueList == null) {
				contextValueList = new ArrayList<>();
			}
			Register contextReg = program.getProgramContext().getRegister(contextRegName);
			if (contextReg != null) {
				contextValueList.add(new RegisterValue(contextReg, value));
			}
		}

		@Override
		public void restoreXml(XmlPullParser parser) {
			XmlElement el = parser.start("setcontext");
			contextRegName = el.getAttribute("name");
			long val = SpecXmlUtils.decodeLong(el.getAttribute("value"));
			value = BigInteger.valueOf(val);
			parser.end();
		}

		public String getName() {
			return contextRegName;
		}

		public BigInteger getValue() {
			return value;
		}

	}

	@Override
	public boolean canAnalyze(Program program) {
		ProgramDecisionTree patternDecisionTree = getPatternDecisionTree();
		boolean hasPatterns = Patterns.hasPatternFiles(program, patternDecisionTree);

		return hasPatterns;
	}

	public AddressSetPropertyMap getOrCreatePotentialMatchPropertyMap(Program program) {
		if (potentialMatchAddressSetPropertyMap != null) {
			return potentialMatchAddressSetPropertyMap;
		}
		potentialMatchAddressSetPropertyMap =
			program.getAddressSetPropertyMap(PRE_FUNCTION_MATCH_PROPERTY_NAME);
		if (potentialMatchAddressSetPropertyMap != null) {
			return potentialMatchAddressSetPropertyMap;
		}

		try {
			potentialMatchAddressSetPropertyMap =
				program.createAddressSetPropertyMap(PRE_FUNCTION_MATCH_PROPERTY_NAME);
		}
		catch (DuplicateNameException e) {
			throw new AssertException(
				"Can't get DuplicateNameException since we tried to get it first");
		}

		return potentialMatchAddressSetPropertyMap;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		SequenceSearchState root = initialize(program);
		if (root == null) {
			String message = "Could not initialize a search state.";
			log.appendMsg(getName(), message);
			log.setStatus(message);

			return false;
		}

		boolean doExecutableBlocksOnly = checkForExecuteBlock(program) && executableBlocksOnly;

		// clear out any previous potential matches, because we are re-looking at these places
		//   this will keep cruft from accumulating in the property map.
		getOrCreatePotentialMatchPropertyMap(program).remove(set);

		MemoryBytePatternSearcher patternSearcher;
		patternSearcher = new MemoryBytePatternSearcher("Function Starts", root) {

			@Override
			public void preMatchApply(MatchAction[] actions, Address addr) {
				contextValueList = null; // make sure, only context from these actions used
			}

			@Override
			public void postMatchApply(MatchAction[] actions, Address addr) {
				// Actions might have set context, check if postcondition failed first
				if (!postreqFailedResult.contains(addr)) {
					setCurrentContext(program, addr);
				}
				// get rid of the context list.
				contextValueList = null;
			}
		};
		patternSearcher.setSearchExecutableOnly(doExecutableBlocksOnly);

		patternSearcher.search(program, set, monitor);

		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		if (!disassemResult.isEmpty()) {
			analysisManager.disassemble(disassemResult);
		}
		analysisManager.setProtectedLocations(codeLocations);

		if (!potentialFuncResult.isEmpty()) {
			// could be a pattern that said this is a function start, so it isn't potentially anymore
			potentialFuncResult = potentialFuncResult.subtract(funcResult);

			// kick off a later analyzer to create the functions after all the fallout
			//       it should check that the function is not already part of another function
			analysisManager.scheduleOneTimeAnalysis(new AnalyzerAdapter(
				FUNCTION_START_SEARCH + " delayed", AnalysisPriority.DATA_ANALYSIS.after()) {
				@Override
				public boolean added(Program addedProgram, AddressSetView addedSet,
						TaskMonitor addedMonitor, MessageLog addedLog) throws CancelledException {
					AddressIterator addresses = addedSet.getAddresses(true);
					while (addresses.hasNext() && !addedMonitor.isCancelled()) {
						Address address = addresses.next();
						// if there are any conditional references, then this can't be a function start
						ReferenceIterator referencesTo =
							addedProgram.getReferenceManager().getReferencesTo(address);
						while (referencesTo.hasNext()) {
							Reference reference = referencesTo.next();
							if (reference.getReferenceType().isConditional()) {
								continue;
							}

						}
						Function funcAt =
							addedProgram.getFunctionManager().getFunctionContaining(address);
						if (funcAt != null) {
							if (funcAt.getEntryPoint().equals(address)) {
								continue;
							}
							BookmarkManager bookmarkManager = addedProgram.getBookmarkManager();
							bookmarkManager.setBookmark(address, BookmarkType.ANALYSIS,
								getName() + " Overlap",
								"Function exists at probable good function start");
							continue;
						}
						new CreateFunctionCmd(address, false).applyTo(addedProgram, addedMonitor);
					}
					return true;
				}
			}, potentialFuncResult);
		}

		if (!funcResult.isEmpty()) {
			// pattern said this is a functions start, kick of creation later
			analysisManager.createFunction(funcResult, false);
		}
		return true;
	}

	/**
	 * @return true - if there are any blocks marked executable
	 */
	private boolean checkForExecuteBlock(Program program) {
		MemoryBlock[] blocks = program.getMemory().getBlocks();

		for (MemoryBlock block : blocks) {
			if (block.isExecute()) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_DATABLOCKS, OPTION_DEFAULT_DATABLOCKS, null,
			OPTION_DESCRIPTION_DATABLOCKS);

		options.registerOption(OPTION_NAME_BOOKMARKS, setbookmark, null,
			OPTION_DESCRIPTION_BOOKMARKS);

	}

	@Override
	public void optionsChanged(Options options, Program program) {

		boolean datablocks = options.getBoolean(OPTION_NAME_DATABLOCKS, OPTION_DEFAULT_DATABLOCKS);
		executableBlocksOnly = !datablocks;

		setbookmark = options.getBoolean(OPTION_NAME_BOOKMARKS, setbookmark);
	}

	protected SequenceSearchState initialize(Program program) {

		potentialFuncResult = new AddressSet();
		disassemResult = new AddressSet();
		codeLocations = new AddressSet();
		postreqFailedResult = new AddressSet();
		funcResult = new AddressSet();

		if (explicitState != null) {
			return explicitState;
		}

		// TODO: Check the times on the patterns files, maybe reload them!
		//       could get times of all files and record them to check times.
		//       filelist keeps getting re-parsed...!
		if (rootState != null) {
			return rootState;
		}

		ArrayList<Pattern> patternlist = new ArrayList<>();
		try {
			ProgramDecisionTree patternDecisionTree = getPatternDecisionTree();
			ResourceFile[] fileList = Patterns.findPatternFiles(program, patternDecisionTree);
			patternlist = readPatterns(fileList, program);
		}
		catch (Exception e) {
			Msg.error(this, "Couldn't load pattern files", e);
			return null;
		}
		if (patternlist == null) {
			return null;
		}
		if (patternlist.size() == 0) {
			return null;
		}

		SequenceSearchState root = SequenceSearchState.buildStateMachine(patternlist);

		return root;
	}

	private ArrayList<Pattern> readPatterns(ResourceFile[] filelist, Program program) {
		ArrayList<Pattern> patlist = new ArrayList<>();
		boolean success = true;
		for (ResourceFile element : filelist) {
			try {
				Pattern.readPatterns(element, patlist, this);
			}
			catch (Exception e) {
				Msg.error(this, "Pattern file error (" + element.getAbsolutePath() + ")", e);
				success = false;
			}
		}
		if (!success) {
			return null;
		}
		return patlist;
	}

	@Override
	public MatchAction getMatchActionByName(String nm) {
		if (nm.equals("funcstart")) {
			return new FunctionStartAction();
		}
		else if (nm.equals("possiblefuncstart")) {
			return new PossibleFunctionStartAction();
		}
		else if (nm.equals("codeboundary")) {
			return new CodeBoundaryAction();
		}
		else if (nm.equals("setcontext")) {
			return new ContextAction();
		}
		return null;
	}

	@Override
	public PostRule getPostRuleByName(String nm) {
		if (nm.equals("align")) {
			return new AlignRule();
		}
		return null;
	}

}
