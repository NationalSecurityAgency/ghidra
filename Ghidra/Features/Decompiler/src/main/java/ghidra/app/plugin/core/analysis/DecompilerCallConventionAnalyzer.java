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

import java.io.IOException;

import generic.cache.CachingPool;
import generic.cache.CountingBasicFactory;
import generic.concurrent.*;
import ghidra.app.cmd.function.DecompilerParallelConventionAnalysisCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.AcyclicCallGraphBuilder;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.AbstractDependencyGraph;
import ghidra.util.task.TaskMonitor;

public class DecompilerCallConventionAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Call Convention ID";
	private static final String DESCRIPTION =
		"Uses decompiler to figure out unknown calling conventions.";

	private static final String COULD_NOT_RECOVER_CALLING_CONVENTION =
		"Could not recover calling convention";
	private static final String OPTION_NAME_DECOMPILER_TIMEOUT_SECS =
		"Analysis Decompiler Timeout (sec)";
	private static final String OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS =
		"Set timeout in seconds for analyzer decompiler calls.";
	public static final int OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS = 60;
	private int decompilerTimeoutSecondsOption = OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS;

	private boolean ignoreBookmarks = false;

//==================================================================================================
// Interface Methods
//==================================================================================================	

	public DecompilerCallConventionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_SIGNATURES_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean can = program.getLanguage().supportsPcode();

		// for a single entry compiler convention, the convention is always used, so no need to identify it
		can &= program.getCompilerSpec().getCallingConventions().length > 1;
		return can;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, decompilerTimeoutSecondsOption,
			null, OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS);
		optionsChanged(options, program);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		decompilerTimeoutSecondsOption =
			options.getInt(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, decompilerTimeoutSecondsOption);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		ignoreBookmarks = set.hasSameAddresses(program.getMemory());

		try {
			AddressSetView functionEntries = findLocations(program, set, monitor);
			if (functionEntries.isEmpty()) {
				return true;
			}

			runDecompilerAnalysis(program, functionEntries, monitor);
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

//==================================================================================================
// End Interface Methods
//==================================================================================================	

	private void runDecompilerAnalysis(Program program, AddressSetView functionEntries,
			TaskMonitor monitor) throws InterruptedException, Exception {

		CachingPool<DecompInterface> decompilerPool =
			new CachingPool<>(new DecompilerFactory(program));
		QRunnable<Address> callback = new ParallelDecompilerCallback(decompilerPool, program);

		ConcurrentGraphQ<Address> queue = null;

		monitor.initialize(functionEntries.getNumAddresses());

		try {
			monitor.setMessage(NAME + " - creating dependency graph...");
			AcyclicCallGraphBuilder builder =
				new AcyclicCallGraphBuilder(program, functionEntries, true);
			AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(monitor);
			if (graph.isEmpty()) {
				return;
			}

			GThreadPool pool = AutoAnalysisManager.getSharedAnalsysThreadPool();
			queue = new ConcurrentGraphQ<>(callback, graph, pool, monitor);

			monitor.setMessage(NAME + " - analyzing call conventions...");
			monitor.initialize(graph.size());

			queue.execute();
		}
		finally {
			if (queue != null) {
				queue.dispose();
			}
			decompilerPool.dispose();
		}
	}

	private void performConventionAnalysis(Function function, DecompInterface decompiler,
			TaskMonitor monitor) {
		DecompilerParallelConventionAnalysisCmd cmd = new DecompilerParallelConventionAnalysisCmd(
			function, decompiler, decompilerTimeoutSecondsOption);
		boolean applyTo = cmd.applyTo(function.getProgram(), monitor);

		// there was an error recovering, mark it so we don't do it again.
		if (!applyTo) {
			BookmarkManager bkMgr = function.getProgram().getBookmarkManager();
			bkMgr.setBookmark(function.getEntryPoint(), BookmarkType.WARNING,
				COULD_NOT_RECOVER_CALLING_CONVENTION, cmd.getStatusMsg());
		}
	}

	private AddressSetView findLocations(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {

		AddressSet functionEntries = new AddressSet();

		FunctionIterator functions = program.getFunctionManager().getFunctions(set, true);

		// must be a function defined
		BookmarkManager bkMgr = program.getBookmarkManager();

		for (Function function : functions) {
			monitor.checkCanceled();

			// must not be a bookmark here, and paying attention to bookmarks
			if (!ignoreBookmarks) {
				Bookmark bookmark = bkMgr.getBookmark(function.getEntryPoint(),
					BookmarkType.WARNING, COULD_NOT_RECOVER_CALLING_CONVENTION);
				if (bookmark != null) {
					continue;
				}
			}

			// must not be thunk or inline
			if (function.isThunk() || function.isInline()) {
				continue;
			}

			if (function.isExternal()) {
				continue;
			}

			// don't do call fixup
			if (function.getCallFixup() != null) {
				continue;
			}

			// must be an unknown signature
			String callingConventionName = function.getCallingConventionName();

			if (!callingConventionName.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING)) {
				continue;
			}

			// don't touch custom storage
			if (function.hasCustomVariableStorage()) {
				continue;
			}

			if (hasImportedSignatureWithinNamespace(function) ||
				hasDefinedParameterTypes(function)) {
				functionEntries.add(function.getEntryPoint());
			}
		}

		return functionEntries;
	}

	private boolean hasImportedSignatureWithinNamespace(Function function) {
		return function.getSignatureSource() == SourceType.IMPORTED &&
			function.getParentNamespace().getID() != Namespace.GLOBAL_NAMESPACE_ID;
	}

	private boolean hasDefinedParameterTypes(Function function) {
		ParameterDefinition[] arguments = function.getSignature().getArguments();
		for (ParameterDefinition parameterDefinition : arguments) {
			DataType dataType = parameterDefinition.getDataType();
			if (dataType == DefaultDataType.dataType || Undefined.isUndefined(dataType)) {
				continue;
			}
			return true;
		}
		return false;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DecompilerFactory extends CountingBasicFactory<DecompInterface> {

		private Program program;

		DecompilerFactory(Program program) {
			this.program = program;
		}

		@Override
		public DecompInterface doCreate(int itemNumber) throws IOException {
			return DecompilerParallelConventionAnalysisCmd.createDecompilerInterface(program);
		}

		@Override
		public void doDispose(DecompInterface decompiler) {
			decompiler.dispose();
		}
	}

	private class ParallelDecompilerCallback implements QRunnable<Address> {

		private CachingPool<DecompInterface> pool;
		private Program program;

		ParallelDecompilerCallback(CachingPool<DecompInterface> decompilerPool, Program program) {
			this.pool = decompilerPool;
			this.program = program;
		}

		@Override
		public void run(Address address, TaskMonitor monitor) throws Exception {
			if (monitor.isCancelled()) {
				return;
			}

			DecompInterface decompiler = pool.get();
			try {
				Function function = program.getFunctionManager().getFunctionAt(address);

				monitor.setMessage(getName() + " - decompile " + function.getName());
				performConventionAnalysis(function, decompiler, monitor);
			}
			finally {
				pool.release(decompiler);
				monitor.incrementProgress(1);
			}
			return;
		}
	}
}
