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
package ghidra.app.cmd.function;

import java.io.IOException;
import java.util.Iterator;
import java.util.Set;

import generic.cache.CachingPool;
import generic.cache.CountingBasicFactory;
import generic.concurrent.*;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.AcyclicCallGraphBuilder;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.graph.AbstractDependencyGraph;
import ghidra.util.task.TaskMonitor;

public class DecompilerParameterIdCmd extends BackgroundCommand {

	private AddressSet entryPoints = new AddressSet();
	private Program program;

	private SourceType sourceTypeClearLevel;
	private boolean commitDataTypes;
	private boolean commitVoidReturn;
	private int decompilerTimeoutSecs;

	public DecompilerParameterIdCmd(String name, AddressSetView entries,
			SourceType sourceTypeClearLevel,
			boolean commitDataTypes, boolean commitVoidReturn, int decompilerTimeoutSecs) {
		super(name, true, true, false);
		entryPoints.add(entries);
		this.sourceTypeClearLevel = sourceTypeClearLevel;
		this.commitDataTypes = commitDataTypes;
		this.commitVoidReturn = commitVoidReturn;
		this.decompilerTimeoutSecs = decompilerTimeoutSecs;
	}

	@Override
	public boolean applyTo(DomainObject obj, final TaskMonitor monitor) {
		program = (Program) obj;

		CachingPool<DecompInterface> decompilerPool =
			new CachingPool<>(new DecompilerFactory());
		QRunnable<Address> runnable = new ParallelDecompileRunnable(decompilerPool);

		ConcurrentGraphQ<Address> queue = null;

		try {
			monitor.setMessage(getName() + " - creating dependency graph...");
			AcyclicCallGraphBuilder builder =
				new AcyclicCallGraphBuilder(program, entryPoints, true);
			AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(monitor);
			if (graph.isEmpty()) {
				return true;
			}

			GThreadPool pool = AutoAnalysisManager.getSharedAnalsysThreadPool();
			queue = new ConcurrentGraphQ<>(runnable, graph, pool, monitor);

			resetFunctionSourceTypes(graph.getValues(), monitor);

			monitor.setMessage(getName() + " - analyzing...");
			monitor.initialize(graph.size());

			queue.execute();
		}
		catch (CancelledException e) {
			// ok, just quit
		}
		catch (Exception e) {
			setStatusMsg(e.getMessage());
			return false;
		}
		finally {
			if (queue != null) {
				queue.dispose();
			}
			decompilerPool.dispose();
		}

		return true;
	}

	/*
	 * The method indicates whether the function is in a block of code that is considered external or "glue"--meaning
	 *  that we don't want to analyze the code that might be there, yet we might have signatures for the function or
	 *  what it provides linkage to that we do not want to wipe.  We want to keep what is already there.
	 *  TODO: This implementation below, with hard-coded specific block names (other than EXTERNAL, which is created
	 *  by analysis) will need to be revisited.  Perhaps a flag will be set by the importer on the blocks that we should
	 *  ignore.
	 */
	private boolean funcIsExternalGlue(Function func) {
		String blockName = program.getMemory().getBlock(func.getEntryPoint()).getName();
		return (blockName.equals(MemoryBlock.EXTERNAL_BLOCK_NAME) || blockName.equals(".plt") ||
			blockName.equals("__stub_helper"));
	}

	private void resetFunctionSourceTypes(Set<Address> set, TaskMonitor monitor)
			throws CancelledException {

		FunctionManager functionManager = program.getFunctionManager();
		// For those functions that we will process, appropriately clear SourceType, meaning
		// move ANALYSIS (or other, depending on ClearLevel) SourceType back to DEFAULT SourceType,
		// but keep higher SoureTypes fixed.  Should we do this for individual parameters and
		// returns too? --> yes/no TODO

		monitor.setMessage(getName() + " - resetting function source types...");
		monitor.initialize(set.size());

		for (Address entryPoint : set) {

			monitor.checkCanceled();
			monitor.incrementProgress(1);

			Function func = functionManager.getFunctionAt(entryPoint);
			try {
				//Do not clear prototypes of "pseudo-analyzed" external functions.
				if (func.isExternal()) {
					continue;
				}
				if (funcIsExternalGlue(func)) {
					continue;
				}

				// TODO: should refactor to avoid changing source type to default
				// since decompile could fail and leave the source types changed.
				Parameter retParam = func.getReturn();
				if (retParam != null) {
					if (!retParam.getSource().isHigherPriorityThan(sourceTypeClearLevel)) {
						func.setReturn(retParam.getDataType(), retParam.getVariableStorage(),
							SourceType.DEFAULT);
					}
				}
				if (!func.getSignatureSource().isHigherPriorityThan(sourceTypeClearLevel)) {
					func.setSignatureSource(SourceType.DEFAULT);
				}
			}
			catch (InvalidInputException e) {
				Msg.warn(this,
					"Error changing signature SourceType on " + func.getName(), e);
			}
		}
	}

	private void analyzeFunction(DecompInterface decomplib, Function f, TaskMonitor monitor) {

		// TODO: in addition to signature-source-type we should also verify that a named calling
		// has been specified since auto-storage assignments may be based on the incorrect default
		// (or unknown) calling convention.

		// TODO: How should we handle cases with unassigned storage on one or more parameters
		// but with good type info and a non-default source type

		if (f == null || f.isThunk() || f.getSignatureSource() != SourceType.DEFAULT) {
			return;
		}

		//We didn't "wipe" previous results of external functions, but we also do not want
		// to set new results.
		if (f.isExternal()) {
			return;
		}
		if (funcIsExternalGlue(f)) {
			return;
		}

		try {
			DecompileResults decompRes = null;
			if (monitor.isCancelled()) {
				return;
			}

			decompRes = decomplib.decompileFunction(f, decompilerTimeoutSecs, monitor);
			setStatusMsg(decompRes.getErrorMessage());

			if (monitor.isCancelled()) {
				return;
			}

			boolean goodInfo = false;
			if (decompRes.decompileCompleted()) {
				// if results lack sanity, don't store them
				if (hasInconsistentResults(decompRes)) {
					setStatusMsg("Error function " + decompRes.getFunction() +
						" has inconsistent parameters");
					return;
				}

				if (commitDataTypes) {
					HighFunction hfunc = decompRes.getHighFunction();
					if (hfunc == null) {
						return;
					}
					HighFunctionDBUtil.commitParamsToDatabase(hfunc, true, SourceType.ANALYSIS);
					boolean commitReturn = true;
					if (!commitVoidReturn) {
						DataType returnType = hfunc.getFunctionPrototype().getReturnType();
						if (returnType instanceof VoidDataType) {
							commitReturn = false;
						}
					}
					if (commitReturn) {
						HighFunctionDBUtil.commitReturnToDatabase(hfunc, SourceType.ANALYSIS);
					}
					goodInfo = true;
				}
				else {
					HighParamID hparamid = decompRes.getHighParamID();

					hparamid.storeParametersToDatabase(commitDataTypes, SourceType.ANALYSIS);

					// Not doing anything with ExtraPop or setStackPurgeSize(int change)
					hparamid.storeReturnToDatabase(commitDataTypes, SourceType.ANALYSIS);
					goodInfo = true;
				}

				checkModelNameConsistency(decompRes.getFunction());
			}

			if (!monitor.isCancelled() && !goodInfo) {
				String msg = getStatusMsg();
				msg = msg == null ? "" : ": " + msg;
				Msg.debug(this, "  Failed to decompile function: " + f.getName() + msg);
			}
		}
		catch (Exception e) {
			if (!monitor.isCancelled()) {
				String errMsg = e.getMessage();
				if (errMsg == null) {
					errMsg = "Error decompiling function: " + e;
				}
				setStatusMsg(errMsg);
			}
		}
	}

	/**
	 * Check for consistency of returned results.  Trying to propagate, don't want to propagate garbage.
	 * 
	 * @param decompRes the decompile result
	 * @return true if inconsistent results
	 */
	private boolean hasInconsistentResults(DecompileResults decompRes) {
		HighFunction hfunc = decompRes.getHighFunction();

		if (hfunc == null) {
			return false;
		}

		Iterator<HighSymbol> symIter = hfunc.getLocalSymbolMap().getSymbols();
		while (symIter.hasNext()) {
			HighSymbol sym = symIter.next();
			HighVariable highVar = sym.getHighVariable();
			if (!(highVar instanceof HighLocal)) {
				continue;
			}

			if (!sym.getName().startsWith("in_")) {
				continue;
			}
			// TODO: THIS IS A HACK!
			if (sym.getName().equals("in_FS_OFFSET")) {
				continue;
			}
			if (!sym.getStorage().isRegisterStorage()) {
				continue;
			}

			Function func = hfunc.getFunction();
			if (func != null) {
				Address entryPoint = func.getEntryPoint();
				BookmarkManager bookmarkManager =
					hfunc.getFunction().getProgram().getBookmarkManager();
				bookmarkManager.setBookmark(
					entryPoint,
					BookmarkType.WARNING,
					"DecompilerParamID",
					"Problem recovering parameters in function " + func.getName() + " at " +
						func.getEntryPoint() + " unknown input variable " + sym.getName());
			}
			return true;

			// TODO: should unaff_ be checked?

			// TODO: should weird stack references be checked?
		}

		return false;
	}

	private void checkModelNameConsistency(Function func) {
		int paramCount = func.getParameterCount();

		String modelName = func.getCallingConventionName();

		if (func.getStackPurgeSize() == 0 && paramCount > 0 &&
			modelName.equals(CompilerSpec.CALLING_CONVENTION_stdcall)) {
			try {
				func.setCallingConvention(CompilerSpec.CALLING_CONVENTION_cdecl);
			}
			catch (InvalidInputException e) {
				setStatusMsg("Invalid Calling Convention " + CompilerSpec.CALLING_CONVENTION_cdecl +
					" : " + e);
			}
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DecompilerFactory extends CountingBasicFactory<DecompInterface> {

		@Override
		public DecompInterface doCreate(int itemNumber) throws IOException {
			DecompInterface decompiler = new DecompInterface();
			decompiler.toggleCCode(false);

			if (commitDataTypes) {
				decompiler.toggleSyntaxTree(false);
				decompiler.setSimplificationStyle("decompile");
			}
			else {
				decompiler.toggleParamMeasures(true);
				decompiler.toggleSyntaxTree(false);
				decompiler.setSimplificationStyle("paramid");
			}

			// Set decompiler up with default options for now and any grabbed from the program.
			// TODO: this should use the options from the tool somehow.
			//       unfortunately what is necessary is not here.
			DecompileOptions opts = new DecompileOptions();
			// turn off elimination of dead code, switch could be there.
			opts.setEliminateUnreachable(false);
			opts.grabFromProgram(program);
			decompiler.setOptions(opts);
			decompiler.openProgram(program);
			return decompiler;
		}

		@Override
		public void doDispose(DecompInterface decompiler) {
			decompiler.dispose();
		}
	}

	private class ParallelDecompileRunnable implements QRunnable<Address> {

		private CachingPool<DecompInterface> pool;

		ParallelDecompileRunnable(CachingPool<DecompInterface> decompilerPool) {
			this.pool = decompilerPool;
		}

		@Override
		public void run(Address address, TaskMonitor monitor) throws CancelledException, Exception {

			DecompInterface decompiler = pool.get();
			try {
				Function function = program.getFunctionManager().getFunctionAt(address);
				doWork(function, decompiler, monitor);
			}
			finally {
				pool.release(decompiler);
				monitor.incrementProgress(1);
			}
		}

		private void doWork(Function function, DecompInterface decompiler, TaskMonitor monitor)
				throws CancelledException {
			monitor.checkCanceled();
			monitor.setMessage(getName() + " - decompile " + function.getName());
			analyzeFunction(decompiler, function, monitor);
		}

	}

}
