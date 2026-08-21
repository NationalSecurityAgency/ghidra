/* ###
 * IP: GHIDRA
 * NOTE: Need to review if these patterns are any indicators of code/original binary, even the address examples
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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class HexagonThunkAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Hexagon Thunks";
	private static final String DESCRIPTION =
		"Detects common Thunk pattern used within Hexagon code";

	/**
	 * <code>THUNK_PATTERN1</code>
	 * <pre>
	 *	1d 7f fd bf                      add                           SP,SP,#-0x8 
	 *	fe fc 9d a7                   || memw                          (SP+#-0x8),R28
	 *	aa ca bc 72                      assign                        R28.H,#0x8aaa
	 *	aa cb bc 71                      assign                        R28.L,#0x8baa
	 *	1d 41 1d b0                      add                           SP,SP,#0x8
	 *	00 40 9c 52                   || jumpr                         R28
	 *	1c c0 9d 91                   || memw                          R28,(SP)
	 * </pre>
	 */
	private static final String THUNK_PATTERN1 =
		"0x1d7ffdbf 0xfefc9da7 " + "..................11110001110010 " // first assign .H
			+ "..................11110001110001 " // second assign .L
			+ "0x1d411db0 0x00409c52 0x1cc09d91";

	private final static String PROCESSOR_NAME = "Hexagon";

	private BulkPatternSearcher<Pattern> sequenceSearchState;

	public HexagonThunkAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!PROCESSOR_NAME.equals(program.getLanguage().getProcessor().toString())) {
			return false;
		}
		return true;
	}

	private BulkPatternSearcher<Pattern> getSequenceSearchState() {
		if (sequenceSearchState == null) {
			List<Pattern> thunkPatterns = new ArrayList<Pattern>();
			thunkPatterns.add(new Pattern(new DittedBitSequence(THUNK_PATTERN1), 0,
				new PostRule[0], new MatchAction[0]));
			sequenceSearchState = new BulkPatternSearcher<Pattern>(thunkPatterns);
		}
		return sequenceSearchState;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		monitor.setMessage("Search for Thunks...");

		BulkPatternSearcher<Pattern> searchState = getSequenceSearchState();

		long numAddrs = 0;
		monitor.initialize(set.getNumAddresses());

		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (int i = 0; i < blocks.length; ++i) {
			monitor.setProgress(numAddrs);
			MemoryBlock block = blocks[i];

			numAddrs += block.getSize();

			try {
				if (set.intersects(block.getStart(), block.getEnd())) {
					searchBlock(searchState, program, block, set, monitor, log);
				}
			}
			catch (IOException e) {
				log.appendMsg("Unable to scan block " + block.getName() + " for function starts");
			}
		}

		return true;
	}

	private void searchBlock(BulkPatternSearcher<Pattern> searchState, Program program,
			MemoryBlock block,
			AddressSetView restrictSet, TaskMonitor monitor, MessageLog log) throws IOException,
			CancelledException {

		// if no restricted set, make restrict set the full block
		AddressSet doneSet = new AddressSet(restrictSet);
		if (doneSet.isEmpty()) {
			doneSet.addRange(block.getStart(), block.getEnd());
		}
		doneSet = doneSet.intersectRange(block.getStart(), block.getEnd());

		long currentProgress = monitor.getProgress();

		// pull each range off the restricted set
		AddressRangeIterator addressRanges = doneSet.getAddressRanges();
		while (addressRanges.hasNext()) {
			monitor.checkCancelled();
			AddressRange addressRange = addressRanges.next();

			monitor.setProgress(currentProgress);

			currentProgress += addressRange.getLength();

			ArrayList<Match<Pattern>> mymatches = new ArrayList<>();

			Address blockStartAddr = block.getStart();

			long blockOffset = addressRange.getMinAddress().subtract(blockStartAddr);

			if (blockOffset <= 0) {
				// don't go before the block start
				blockOffset = 0;
			}

			// compute number of bytes in the range + 1, and don't search more than that.
			long maxBlockSearchLength =
				addressRange.getMaxAddress().subtract(blockStartAddr) - blockOffset + 1;

			InputStream data = block.getData();
			data.skip(blockOffset);

			searchState.search(data, maxBlockSearchLength, mymatches, monitor);
			monitor.checkCancelled();

			// TODO: DANGER there is much offset<-->address calculation here
			//       should be OK, since they are all relative to the block.
			for (int i = 0; i < mymatches.size(); ++i) {
				monitor.checkCancelled();
				Match<Pattern> match = mymatches.get(i);
				Pattern pattern = match.getPattern();
				long offset = blockOffset + match.getStart() + pattern.getMarkOffset();
				Address addr = blockStartAddr.add(offset);
				createThunk(program, addr, monitor, log);
			}
		}
	}

	private Address getThunkDestination(Function thunk, AddressSetView body) {

		Listing listing = thunk.getProgram().getListing();
		Instruction lastInstr = listing.getInstructionContaining(body.getMaxAddress());
		if (lastInstr == null) {
			return null;
		}
		FlowType flowType = lastInstr.getFlowType();
		if (!flowType.isCall() && !flowType.isJump()) {
			return null;
		}
		Reference flowRef = null;
		for (Reference ref : lastInstr.getReferencesFrom()) {
			RefType refType = ref.getReferenceType();
			if (!refType.isFlow()) {
				continue;
			}
			if (flowRef != null) {
				return null;
			}
			if (!refType.isCall() && !refType.isJump()) {
				return null;
			}
			flowRef = ref;
		}
		return flowRef != null ? flowRef.getToAddress() : null;
	}

	private void createThunk(Program program, Address addr, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// check existing function first
		Function func = program.getFunctionManager().getFunctionAt(addr);

		if (func != null && func.isThunk()) {
			return;
		}

		// no instruction, ignore it
		Instruction instruction = program.getListing().getInstructionAt(addr);
		if (instruction == null) {
			return;
		}

		// don't know a body, make a dummy
		AddressSet body;
		body = new AddressSet(addr, addr.add(27));

		// first get function to destination
		// use the symbolic propagator to lay down the reference (restricted to this body).
		SymbolicPropogator symEval = new SymbolicPropogator(program);

		symEval.flowConstants(addr, body, null, true, monitor);

		// if the found snippet is fallen into, at least get the to ref, so if
		//    this is found to be a thunk later, the reference is already there.

		// instruction falling into it, not a thunk
		//   instruction must not be a jump to this location either.
		Address fallFrom = instruction.getFallFrom();
		if (fallFrom != null) {
			Instruction fromInstr = program.getListing().getInstructionAt(fallFrom);
			if (fromInstr != null) {
				FlowType flowType = fromInstr.getFlowType();
				if (!flowType.isJump() || flowType.isConditional()) {
					return;
				}
				Reference[] referencesFrom = fromInstr.getReferencesFrom();
				for (int i = 0; i < referencesFrom.length; i++) {
					if (!referencesFrom.equals(addr)) {
						return;
					}
				}
			}
		}

		// Then create the body.	

		if (func == null) {
			// must create it
			CreateFunctionCmd createFunctionCmd =
				new CreateFunctionCmd(null, addr, body, SourceType.ANALYSIS);
			createFunctionCmd.applyTo(program);
			func = program.getFunctionManager().getFunctionAt(addr);
		}
		if (func == null) {
			return;
		}

		Address thunkDest = getThunkDestination(func, body);
		if (thunkDest == null) {
			return;
		}

		Listing listing = func.getProgram().getListing();

		FunctionManager funcMgr = func.getProgram().getFunctionManager();
		Function thunkedFunc = funcMgr.getFunctionAt(thunkDest);
		if (thunkedFunc == null) {

			Instruction instr = listing.getInstructionAt(thunkDest);
			if (instr == null) {
				return;
			}

			CreateFunctionCmd cmd = new CreateFunctionCmd(thunkDest);
			cmd.applyTo(func.getProgram());

			thunkedFunc = funcMgr.getFunctionAt(thunkDest);
			if (thunkedFunc == null) {
				return;
			}
		}

		func.setThunkedFunction(thunkedFunc);

	}
}
