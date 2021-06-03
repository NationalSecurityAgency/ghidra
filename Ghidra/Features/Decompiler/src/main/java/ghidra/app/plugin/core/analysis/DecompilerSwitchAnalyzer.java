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

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import generic.concurrent.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
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

	private boolean hitNonReturningFunction = false;

	private Register isaModeSwitchRegister = null;
	private Register isaModeRegister = null;

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

		isaModeSwitchRegister = program.getRegister("ISAModeSwitch");
		isaModeRegister = program.getRegister("ISA_MODE");

		try {
			ArrayList<Address> locations = findLocations(program, set, monitor);
			if (locations.isEmpty()) {
				return true;
			}

			Set<Function> functions = findFunctions(program, locations, monitor);

			if (hitNonReturningFunction) {
				hitNonReturningFunction = false;
				// if hit a non-returning function, code needs to be fixed up
				//  before wasting time on analyzing potentially bad code
				// This will also clean out locations that were thunks for the next go round.
				restartRemainingLater(program, functions);
				return true;
			}

			runDecompilerAnalysis(program, functions, monitor);
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

	private void restartRemainingLater(Program program, Set<Function> functions) {
		AddressSet funcSet = new AddressSet();
		for (Function function : functions) {
			funcSet.add(function.getBody());
		}
		AutoAnalysisManager.getAnalysisManager(program).scheduleOneTimeAnalysis(
			new DecompilerSwitchAnalyzer(), funcSet);
		Msg.info(this, "hit non-returning function, restarting decompiler switch analyzer later");
	}

//==================================================================================================
// End Interface Methods
//==================================================================================================

	private void runDecompilerAnalysis(Program program, Set<Function> functions,
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

	private Set<Function> findFunctions(final Program program, ArrayList<Address> locations,
			final TaskMonitor monitor) throws InterruptedException, Exception, CancelledException {

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

		Set<Function> functions = new HashSet<>();
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
			functions.add(function);
		}

		return functions;
	}

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
			monitor.checkCanceled();

			Instruction instruction = iterator.next();
			FlowType flowType = instruction.getFlowType();
			if (!flowType.isJump() || !flowType.isComputed()) {
				if (!isCallFixup(program, instruction, flowType)) {
					continue;
				}
			}

			Address address = instruction.getMinAddress();
			locations.add(address);
			long remaining = (maxAddress.getOffset() - address.getOffset()) + address.getSize();
			monitor.setProgress(total - remaining);
		}

		return locations;
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
			BasicBlockModel basicBlockModel = new BasicBlockModel(program);

			return resolveComputableFlow(location, monitor, basicBlockModel);
		}

		/**
		 * resolve the flow destination by computing to a single value
		 *   For large number of potential functions, this should improve switch analysis speed
		 *   
		 * @return true if the flow could be easily resolved.
		 */
		private boolean resolveComputableFlow(Address location, TaskMonitor monitor,
				BasicBlockModel basicBlockModel) throws CancelledException {

			// get the basic block
			//
			// NOTE: Assumption, the decompiler won't get the switch if there is no guard

			final CodeBlock jumpBlockAt =
				basicBlockModel.getFirstCodeBlockContaining(location, monitor);
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
							int pcodeop, Address address, int size, RefType refType) {
						// go ahead and place the reference, since it is a constant.
						if (refType.isComputed() && refType.isFlow() &&
							program.getMemory().contains(address)) {
							propogateCodeMode(context, address);
							foundCount.incrementAndGet();
							return true;
						}
						return false;
					}

					private void propogateCodeMode(VarnodeContext context, Address addr) {
						// get CodeModeRegister and flow it to destination, if it is set here

						if (isaModeSwitchRegister == null) {
							return;
						}
						BigInteger value = context.getValue(isaModeSwitchRegister, false);
						if (value != null && program.getListing().getInstructionAt(addr) == null) {
							try {
								program.getProgramContext().setValue(isaModeRegister, addr, addr,
									value);
							}
							catch (ContextChangeException e) {
								// ignore
							}
						}
					}
				}, false, monitor);

			// only found one reference
			// NOTE: This is overly protective, since we restricted the constant following to the block

			return foundCount.get() == 1;
		}
	}
}
