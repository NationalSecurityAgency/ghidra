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
package ghidra.app.plugin.core.analysis;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;

import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class PPC64CallStubAnalyzer extends AbstractAnalyzer {
	
	private static final String NAME = "PPC64 ELF Call Stubs";
	private static final String DESCRIPTION = "Detect ELF Call Stubs and create thunk function";
	private static final String PROCESSOR_NAME = "PowerPC";
	
	private static final String CALL_STUB_PATTERN_FILE = "ppc64-r2CallStubs.xml";
	
	private static final String UNKNOWN_FUNCTION_NAME = "___UNKNOWN_CALL_STUB___";

	private static boolean patternLoadFailed;
	private static ArrayList<Pattern> beCallStubPatterns;
	private static ArrayList<Pattern> leCallStubPatterns;
	private static int maxPatternLength;
	
	private Register r2Reg;
	private Register ctrReg;
	
	public PPC64CallStubAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before());
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		Language language = program.getLanguage();
		// TODO: what about 32/64 hybrid case?
		if (PROCESSOR_NAME.equals(language.getProcessor().toString()) &&
				language.getLanguageDescription().getSize() == 64 &&
				patternsLoaded(language.isBigEndian())) {
			r2Reg = program.getRegister("r2");
			ctrReg = program.getRegister("CTR");
			return r2Reg != null && ctrReg != null;
		}
		return false;
	}

	private static synchronized boolean patternsLoaded(boolean bigEndian) {
		if (patternLoadFailed) {
			return false;
		}
		
		if (!bigEndian) {
			if (leCallStubPatterns != null) {
				return true;
			}
			if (!patternsLoaded(true)) {
				return false;
			}
			leCallStubPatterns = flipPatterns(beCallStubPatterns);
			return true;
		}
		
		try {
			ResourceFile patternFile = Application.getModuleDataFile(CALL_STUB_PATTERN_FILE);
			
			beCallStubPatterns = new ArrayList<>();
			Pattern.readPatterns(patternFile, beCallStubPatterns, null);
			
			maxPatternLength = 0;
			for (Pattern pattern : beCallStubPatterns) {
				int len = pattern.getSize();
				if ((len % 4) != 0) {
					throw new SAXException("pattern must contain multiple of 4-bytes");
				}
				if (len > maxPatternLength) {
					maxPatternLength = len;
				}
			}
			
		} catch (FileNotFoundException e) {
			Msg.error(PPC64CallStubAnalyzer.class, "PowerPC resource file not found: " + CALL_STUB_PATTERN_FILE);
			patternLoadFailed = true;
			return false;
		} catch (SAXException | IOException e) {
			Msg.error(PPC64CallStubAnalyzer.class, "Failed to parse byte pattern file: " + CALL_STUB_PATTERN_FILE, e);
			patternLoadFailed = true;
			return false;
		}
		
		return true;
	}

	private static ArrayList<Pattern> flipPatterns(ArrayList<Pattern> patternlist) {
		
		ArrayList<Pattern> list = new ArrayList<>();
		for (Pattern pat : patternlist) {
			byte[] bytes = flipPatternBytes(pat.getValueBytes());
			byte[] mask = flipPatternBytes(pat.getMaskBytes());
			Pattern newPattern = new Pattern(new DittedBitSequence(bytes, mask), pat.getMarkOffset(), 
					pat.getPostRules(), pat.getMatchActions());
			list.add(newPattern);
		}
		return list;
	}
	
	private static byte[] flipPatternBytes(byte[] bytes) {
		for (int i = 0; i < bytes.length; i += 4) {
			byte b = bytes[i];
			bytes[i] = bytes[i + 3];
			bytes[i + 3] = b;
			b = bytes[i + 1];
			bytes[i + 1] = bytes[i + 2];
			bytes[i + 2] = b;
		}
		return bytes;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		ProgramContext programContext = program.getProgramContext();
		
		SequenceSearchState sequenceSearchState = SequenceSearchState.buildStateMachine(
				program.getMemory().isBigEndian() ? beCallStubPatterns : leCallStubPatterns);
		
		monitor.setIndeterminate(false);
		monitor.setMaximum(set.getNumAddresses());
		monitor.setProgress(0);
		int functionCount = 0;
		
		// each address should correspond to a function
		for (Function function : listing.getFunctions(set, true)) {
			
			monitor.checkCanceled();
			monitor.setProgress(functionCount++);
			
			Address entryAddr = function.getEntryPoint();
			boolean isThunk = function.isThunk();
			
			Match stubMatch = null;
			if (!isThunk) {
				stubMatch = matchKnownCallStubs(entryAddr, memory, sequenceSearchState);
				if (stubMatch == null) {
					continue; // non-stub
				}
			}
			else if (!thunksUnknownFunction(function)) {
				continue; // previously resolved thunk
			}
			
			RegisterValue r2Value = programContext.getRegisterValue(r2Reg, entryAddr);
			if (r2Value == null || !r2Value.hasValue()) {
				if (!isThunk) { // stubMatch is known
					// Thunk unknown function for future processing once r2 is propagated
					createThunk(program, entryAddr, stubMatch.getSequenceSize(), getUnknownFunction(
						program).getEntryPoint());
				}
				continue;
			}
			
			int stubLength = stubMatch != null ? stubMatch.getSequenceSize()
					: (int) function.getBody().getNumAddresses();
			
			analyzeCallStub(program, function, stubLength, monitor);
		}
		
		return true;
	}

	private Match matchKnownCallStubs(Address addr, Memory memory,
			SequenceSearchState sequenceSearchState) {
		byte[] bytes = new byte[maxPatternLength];
		ArrayList<Match> matches = new ArrayList<>();
		int cnt = 0;
		try {
			cnt = memory.getBytes(addr, bytes);
		}
		catch (MemoryAccessException e) {
			// ignore
		}
		if (cnt == 0) {
			return null;
		}

		byte[] searchBytes = bytes;
		if (cnt != bytes.length) {
			// although rare, shorten searchBytes if unable to fill
			searchBytes = new byte[cnt];
			System.arraycopy(bytes, 0, searchBytes, 0, cnt);
		}

		matches.clear();
		sequenceSearchState.apply(searchBytes, matches);
		if (matches.size() == 0) {
			return null;
		}

		return matches.get(0);
	}

	private void createThunk(Program program, Address stubAddr, int stubLength,
			Address thunkedFunctionAddr) {
		AddressSet stubBody = new AddressSet(stubAddr, stubAddr.add(stubLength - 1));
		CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(stubAddr, stubBody,
			thunkedFunctionAddr);
		cmd.applyTo(program);
	}

	private void analyzeCallStub(Program program, Function stubFunction, int stubLength,
			TaskMonitor monitor) throws CancelledException {
		
		SymbolicPropogator symEval = new SymbolicPropogator(program);
		symEval.setParamRefCheck(false);
		symEval.setReturnRefCheck(false);
		symEval.setStoredRefCheck(false);
		
		Address entryAddr = stubFunction.getEntryPoint();
		AddressSet stubBody = new AddressSet(entryAddr, entryAddr.add(stubLength - 1));
		
		ContextEvaluator eval = new ContextEvaluatorAdapter() {

			@Override
			public boolean followFalseConditionalBranches() {
				return false; // should never happen - just in case
			}
			
			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address,
					int size, RefType refType) {
				return true;
			}
			
			@Override
			public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
				
				// We only handle indirect branch through CTR register
				if (!"bctr".equals(instruction.getMnemonicString())) {
					return true;
				}
				
				// Change bctr flow to call-return
				instruction.setFlowOverride(FlowOverride.CALL_RETURN);
				
				RegisterValue ctrValue = context.getRegisterValue(ctrReg);
				if (ctrValue != null  && ctrValue.hasValue()) {
					Address destAddr = entryAddr.getNewAddress(
						ctrValue.getUnsignedValue().longValue());
					Function destFunction = createDestinationFunction(program, destAddr,
						instruction.getAddress(), context.getRegisterValue(r2Reg), monitor);
					if (destFunction != null) {
						if (!stubFunction.isThunk()) {
							createThunk(program, entryAddr, stubLength,
								destFunction.getEntryPoint());
						}
						else {
							stubFunction.setThunkedFunction(destFunction);
						}
					}
				}
				
				return true;
			}
			
			@Override
			public boolean allowAccess(VarnodeContext context, Address address) {
				return true;
			}
		};
		
		symEval.flowConstants(entryAddr, stubBody, eval, false, monitor);
	}

	private Function getUnknownFunction(Program program) {

		try {
			return program.getExternalManager().addExtFunction(Library.UNKNOWN,
				UNKNOWN_FUNCTION_NAME, null, SourceType.IMPORTED).getFunction();
		}
		catch (InvalidInputException | DuplicateNameException e) {
			throw new AssertException("unexpected", e);
		}
	}

	private boolean thunksUnknownFunction(Function function) {
		Function thunkedFunction = function.getThunkedFunction(false);
		if (thunkedFunction == null || !thunkedFunction.isExternal()) {
			return false;
		}
		return UNKNOWN_FUNCTION_NAME.equals(thunkedFunction.getName());
	}

	private Function createDestinationFunction(Program program, Address addr, Address flowFromAddr,
			RegisterValue regValue, TaskMonitor monitor) {

		Listing listing = program.getListing();
		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		
		if (!program.getMemory().contains(addr)) {
			bookmarkMgr.setBookmark(flowFromAddr, BookmarkType.ERROR, "Bad Reference", "No memory for call stub destination at " + addr);
			return null;
		}
		
		Function function = listing.getFunctionAt(addr);
		
		if (regValue != null && regValue.hasValue()) {
			ProgramContext programContext = program.getProgramContext();
			RegisterValue oldValue = programContext.getRegisterValue(regValue.getRegister(), addr);
			if (oldValue == null || !oldValue.hasValue()) {
				try {
					programContext.setRegisterValue(addr, addr, regValue);
				} catch (ContextChangeException e) {
					throw new AssertException(e);
				}
				if (function != null) {
					AutoAnalysisManager.getAnalysisManager(program).functionDefined(addr);
				}
			}
		}
		if (function != null) {
			return function;
		}
		
		CodeUnit cu = listing.getCodeUnitContaining(addr);
		if (cu == null) {
			throw new AssertException("expected code unit in memory");
		}
		if (!addr.equals(cu.getMinAddress())) {
			bookmarkMgr.setBookmark(cu.getMinAddress(), BookmarkType.ERROR, "Code Unit Conflict", "Expected function entry at " + addr + " referenced by call stub from " + flowFromAddr);
			return null;
		}
		if (cu instanceof Data) {
			Data d = (Data)cu;
			if (d.isDefined()) {
				bookmarkMgr.setBookmark(addr, BookmarkType.ERROR, "Code Unit Conflict", "Expected function entry referenced by call stub from " + flowFromAddr);
				return null;
			}
			DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
			if (!cmd.applyTo(program, monitor)) {
				return null;
			}
		}
		
		CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
		if (cmd.applyTo(program, monitor)) {
			return cmd.getFunction();
		}
		return null;
	}

}
