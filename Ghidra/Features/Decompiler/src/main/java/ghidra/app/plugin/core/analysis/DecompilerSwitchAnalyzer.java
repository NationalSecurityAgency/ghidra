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

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import generic.concurrent.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DecompilerSwitchAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Decompiler Switch Analysis";
	private static final String DESCRIPTION =
		"Creates switch statements for dynamic instructions using Decompiler.";

	private static final String OPTION_NAME_DECOMPILER_TIMEOUT_SECS =
		"Analysis Decompiler Timeout (sec)";
	private static final String OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS =
		"Set timeout in seconds for analyzer decompiler calls.";
	public static final int OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS = 60;
	private int decompilerTimeoutSecondsOption = OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS;

	// cache for pcode callother injection payloads
	private HashMap<Long, InjectPayload> injectPayloadCache = new HashMap<>();

	private boolean hitNonReturningFunction = false;


//==================================================================================================
// Interface Methods
//==================================================================================================

	public DecompilerSwitchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().supportsPcode();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, decompilerTimeoutSecondsOption,
			null, OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		decompilerTimeoutSecondsOption =
			options.getInt(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, decompilerTimeoutSecondsOption);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		try {
			ArrayList<Address> locations = findLocations(program, set, monitor);
			if (locations.isEmpty()) {
				return true;
			}

			List<Function> definedFunctions = new ArrayList<>();
			List<Function> undefinedFunctions = new ArrayList<>();
			findFunctions(program, locations, definedFunctions, undefinedFunctions, monitor);

			if (hitNonReturningFunction) {
				hitNonReturningFunction = false;
				// if hit a non-returning function, code needs to be fixed up
				//  before wasting time on analyzing potentially bad code
				// This will also clean out locations that were thunks for the next go round.
				restartRemainingLater(program, definedFunctions, undefinedFunctions);
				return true;
			}

			monitor.checkCancelled();
			runDecompilerAnalysis(program, definedFunctions, monitor);
			monitor.checkCancelled();
			runDecompilerAnalysis(program, undefinedFunctions, monitor);
			monitor.checkCancelled();
		}
		catch (CancelledException ce) {
			throw ce;
		}
		catch (InterruptedException ie) {
			if (!monitor.isCancelled()) {
				Msg.error(this, "Unexpectedly interrupted while analyzing", ie);
			}
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected exception", e);
		}

		return true;
	}

	private void restartRemainingLater(Program program, Collection<Function> definedFunctions,
			Collection<Function> undefinedFunctions) {
		AddressSet funcSet = new AddressSet();
		for (Function function : definedFunctions) {
			funcSet.add(function.getBody());
		}
		for (Function function : undefinedFunctions) {
			funcSet.add(function.getBody());
		}
		AutoAnalysisManager.getAnalysisManager(program)
				.scheduleOneTimeAnalysis(new DecompilerSwitchAnalyzer(), funcSet);
		Msg.info(this, "hit non-returning function, restarting decompiler switch analyzer later");
	}

//==================================================================================================
// End Interface Methods
//==================================================================================================

	private void runDecompilerAnalysis(Program program, Collection<Function> functions,
			TaskMonitor monitor) throws InterruptedException, Exception {

		DecompilerCallback<Void> callback =
			new DecompilerCallback<Void>(program, new SwitchAnalysisDecompileConfigurer(program)) {

				@Override
				public Void process(DecompileResults results, TaskMonitor m) throws Exception {

					DecompilerSwitchAnalysisCmd cmd = new DecompilerSwitchAnalysisCmd(results);
					cmd.applyTo(program, monitor);
					return null;
				}
			};

		callback.setTimeout(decompilerTimeoutSecondsOption);

		try {
			ParallelDecompiler.decompileFunctions(callback, functions, monitor);
		}
		finally {
			callback.dispose();
		}

	}

	private void findFunctions(Program program, ArrayList<Address> locations,
			Collection<Function> definedFunctions, Collection<Function> undefinedFunctions,
			TaskMonitor monitor) throws InterruptedException, Exception, CancelledException {

		GThreadPool pool = AutoAnalysisManager.getSharedAnalsysThreadPool();
		FindFunctionCallback callback = new FindFunctionCallback(program);

		// @formatter:off
		ConcurrentQ<Address, Function> queue = new ConcurrentQBuilder<Address, Function>()
			.setCollectResults(true)
			.setThreadPool(pool)
			.setMonitor(monitor)
			.build(callback);
		// @formatter:on

		for (Address location : locations) {
			queue.add(location);
		}

		Collection<QResult<Address, Function>> results = queue.waitForResults();

		for (QResult<Address, Function> result : results) {
			Function function = result.getResult();
			if (function == null) {
				continue;
			}
			// kids, don't do thunks
			if (function.isThunk()) {
				if (function.hasNoReturn()) {
					hitNonReturningFunction = true;
				}
				continue;
			}
			if (function instanceof UndefinedFunction) {
				undefinedFunctions.add(function);
			}
			else {
				definedFunctions.add(function);
			}
		}
	}

	/**
	 * Find locations that could be an unrecovered switches
	 * 
	 * @param program program
	 * @param set area of program to check
	 * @param monitor monitor
	 * @return list of addresses that could be a switch
	 * 
	 * @throws CancelledException if monitor cancels
	 */
	private ArrayList<Address> findLocations(Program program, AddressSetView set,
			TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Finding function locations...");
		long total = set.getNumAddresses();
		monitor.initialize(total);
		Address maxAddress = set.getMaxAddress();
		ArrayList<Address> locations = new ArrayList<>();
		Listing list = program.getListing();
		InstructionIterator iterator = list.getInstructions(set, true);
		while (iterator.hasNext()) {
			monitor.checkCancelled();

			Instruction instruction = iterator.next();
			FlowType flowType = instruction.getFlowType();
			if (!flowType.isJump() || !flowType.isComputed()) {
				if (!isCallFixup(program, instruction, flowType)) {
					continue;
				}
			}
			
			// check for break type construct
			if (hasUnrecoverableCallOther(program, instruction)) {
				continue;
			}


			Address address = instruction.getMinAddress();
			locations.add(address);
			long remaining = (maxAddress.getOffset() - address.getOffset()) + address.getSize();
			monitor.setProgress(total - remaining);
		}

		return locations;
	}

	/**
	 * Check an instruction for an unrecoverable computed destination due
	 * to calling a callOther pcode op that has no associated injection.
	 * If there is an associated injection, then it might yet be recoverable.
	 * 
	 * @param program program
	 * @param instr branching instruction to check
	 * @return true if there is a callOther that will block switch recovery
	 */
	private boolean hasUnrecoverableCallOther(Program program, Instruction instr) {
		HashSet<Varnode> callOtherOutputs = new HashSet<Varnode>();

		PcodeOp[] pcode = instr.getPcode(true);
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.CALLOTHER) {
				// if callother has defined pcode inject replacement
				// then could recover
				if (hasPcodeInject(program, op)) {
					continue;
				}
				// save callother output varnode
				Varnode dest = op.getOutput();
				if (dest != null) {
					callOtherOutputs.add(dest);
				}
				continue;
			}
			if (!callOtherOutputs.isEmpty() && op.getOpcode()==PcodeOp.BRANCHIND) {
				// check if branching to an output varnode of callother
				if (callOtherOutputs.contains(op.getInput(0))) {
					// target is computed from a callother output
					return true;
				}
				continue;
			}
			
			// if have a callother destinations, check for it as an input
			if (!callOtherOutputs.isEmpty()) {
				Varnode[] inputs = op.getInputs();
				for (Varnode in : inputs) {
					if (callOtherOutputs.contains(in)) {
						Varnode dest = op.getOutput();
						if (dest != null) {
							callOtherOutputs.add(dest);
						}
					}
				}
			}
		}
		
		return false;
	}

	/**
	 * Check if the callOther Pcode op has an associated injection
	 * 
	 * @param program program
	 * @param op callother pcode op
	 * @return true if there is a pcode injection, false otherwise 
	 */
	private boolean hasPcodeInject(Program program, PcodeOp op) {
		long callOtherIndex = op.getInput(0).getOffset();
		InjectPayload payload = findPcodeInjection(program, callOtherIndex);

		return payload != null;
	}
	
	/**
	 * Find out if a callother pcode op has a pcodeInjection attached to it
	 * 
	 * @param program program
	 * @param callOtherIndex callOther ID index
	 * @return injection payload or null if no register injections
	 */
	private InjectPayload findPcodeInjection(Program program, long callOtherIndex) {
		InjectPayload payload = injectPayloadCache.get(callOtherIndex);

		// has a payload value for the pcode callother index
		if (payload != null) {
			return payload;
		}

		// value null, if contains the key, then already looked up
		if (injectPayloadCache.containsKey(callOtherIndex)) {
			return null;
		}
		PcodeInjectLibrary snippetLibrary = program.getCompilerSpec().getPcodeInjectLibrary();

		String opName = program.getLanguage().getUserDefinedOpName((int) callOtherIndex);

		// segment is special named injection
		if ("segment".equals(opName)) {
			payload =
				snippetLibrary.getPayload(InjectPayload.EXECUTABLEPCODE_TYPE, "segment_pcode");
		}
		else {
			payload = snippetLibrary.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, opName);
		}

		// save payload in cache for next lookup
		injectPayloadCache.put(callOtherIndex, payload);
		return payload;
	}

	private boolean isCallFixup(Program program, Instruction instr, FlowType flowType) {
		if (!flowType.isCall()) {
			return false;
		}

		Reference[] referencesFrom = instr.getReferencesFrom();
		for (Reference reference : referencesFrom) {
			if (reference.getReferenceType().isCall()) {
				Function func =
					program.getFunctionManager().getFunctionAt(reference.getToAddress());
				if (func != null && func.getCallFixup() != null) {
					return true;
				}
			}
		}
		return false;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private class FindFunctionCallback implements QCallback<Address, Function> {

		private Program program;

		FindFunctionCallback(Program program) {
			this.program = program;
		}

		@Override
		public Function process(Address location, TaskMonitor monitor) throws Exception {
			if (monitor.isCancelled()) {
				return null;
			}
			monitor.incrementProgress(1);

			Reference[] referencesFrom = program.getReferenceManager().getReferencesFrom(location);

			// if any flow references, don't do it.
			//   This could be changed to one, for things that might not have gotten all references
			for (Reference element : referencesFrom) {
				RefType referenceType = element.getReferenceType();
				if (referenceType.isComputed()) {
					return null;
				}
			}

			if (handleSimpleBlock(location, monitor)) {
				Instruction instr = program.getListing().getInstructionAt(location);
				if (instr == null || !isCallFixup(program, instr, instr.getFlowType())) {
					// fixup the function body
					Function fixupFunc =
						program.getFunctionManager().getFunctionContaining(location);
					if (fixupFunc != null) {
						CreateFunctionCmd.fixupFunctionBody(program, fixupFunc, monitor);
						// send function back, so non-returning nature will be picked up by decompiler
						if (fixupFunc.hasNoReturn()) {
							return fixupFunc;
						}
						return null;
					}
				}
			}

			Function func = program.getFunctionManager().getFunctionContaining(location);
			if (func == null) {
				func =
					UndefinedFunction.findFunctionUsingSimpleBlockModel(program, location, monitor);
			}

			return func;
		}

		/**
		 * Handle any blocks that have a simple single computable flow with no switch type flow
		 * in it by trying to resolving the reference
		 * 
		 * @return true if this block could be handled as a simple single reference block flow
		 */
		private boolean handleSimpleBlock(Address location, TaskMonitor monitor)
				throws CancelledException {
			SimpleBlockModel blockModel = new SimpleBlockModel(program);

			return resolveComputableFlow(location, monitor, blockModel);
		}

		/**
		 * resolve the flow destination by computing to a single value
		 *   For large number of potential functions, this should improve switch analysis speed
		 *   
		 * @return true if the flow could be easily resolved.
		 */
		private boolean resolveComputableFlow(Address location, TaskMonitor monitor,
				CodeBlockModel blockModel) throws CancelledException {

			// get the basic block
			//
			// NOTE: Assumption, the decompiler won't get the switch if there is no guard

			final CodeBlock jumpBlockAt = blockModel.getFirstCodeBlockContaining(location, monitor);
			// If the jump target can has a computable target with only the instructions in the basic block it is found in
			//  then it isn't a switch statment
			//
			// NOTE: Assumption, we have found all flows leading to the switch that might split the basic block

			final AtomicInteger foundCount = new AtomicInteger(0);
			SymbolicPropogator prop = new SymbolicPropogator(program);
			prop.flowConstants(jumpBlockAt.getFirstStartAddress(), jumpBlockAt,
				new ContextEvaluatorAdapter() {
					@Override
					public boolean evaluateReference(VarnodeContext context, Instruction instr,
							int pcodeop, Address address, int size, DataType dataType, RefType refType) {
						// go ahead and place the reference, since it is a constant.
						if (refType.isComputed() && refType.isFlow() &&
							program.getMemory().contains(address)) {
							foundCount.incrementAndGet();
						}
						return false;
					}
				}, false, monitor);

			// only found one reference
			// NOTE: This is overly protective, since we restricted the constant following to the block

			return foundCount.get() == 1;
		}
	}
}
