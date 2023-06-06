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
import java.util.stream.Collectors;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.services.*;
import ghidra.app.util.bin.format.golang.GoConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.symbol.*;
import ghidra.program.util.FunctionUtility;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class GolangDuffFixupAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Golang Duff Function Fixup";
	private final static String DESCRIPTION = """
			Propagates function signature information from the base runtime.duffcopy \
			and runtime.duffzero functions to the other entry points that were discovered \
			during analysis.""";

	private Program program;
	private TaskMonitor monitor;
	private MessageLog log;

	public GolangDuffFixupAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return GoConstants.GOLANG_CSPEC_NAME.equals(
			program.getCompilerSpec().getCompilerSpecDescription().getCompilerSpecName());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		this.program = program;
		this.monitor = monitor;
		this.log = log;

		Symbol duffzeroSym = SymbolUtilities.getUniqueSymbol(program, "runtime.duffzero");
		Function duffzeroFunc = duffzeroSym != null ? (Function) duffzeroSym.getObject() : null;
		Symbol duffcopySym = SymbolUtilities.getUniqueSymbol(program, "runtime.duffcopy");
		Function duffcopyFunc = duffcopySym != null ? (Function) duffcopySym.getObject() : null;

		List<Function> funcs = new ArrayList<>();
		if (duffzeroFunc != null && duffzeroFunc.getCallingConvention() != null) {
			funcs.add(duffzeroFunc);
		}
		if (duffcopyFunc != null && duffcopyFunc.getCallingConvention() != null) {
			funcs.add(duffcopyFunc);
		}

		if (funcs.isEmpty()) {
			return true;
		}

		Map<Address, AddressSetView> map = getFunctionActualRanges(funcs);

		if (duffzeroFunc != null) {
			updateDuffFuncs(duffzeroFunc, map.get(duffzeroFunc.getEntryPoint()));
		}
		if (duffcopyFunc != null) {
			updateDuffFuncs(duffcopyFunc, map.get(duffcopyFunc.getEntryPoint()));
		}

		return true;
	}

	/**
	 * Copy details from the base duff function to any other unnamed functions that start within
	 * the base duff function's range.
	 * 
	 * @param duffFunc base duff function
	 * @param duffFuncBody the addresses the base function occupies
	 */
	private void updateDuffFuncs(Function duffFunc, AddressSetView duffFuncBody) {
		if (duffFunc == null || duffFuncBody == null) {
			return;
		}
		String duffComment = program.getListing()
				.getCodeUnitAt(duffFunc.getEntryPoint())
				.getComment(CodeUnit.PLATE_COMMENT);
		for (FunctionIterator funcIt =
			program.getFunctionManager().getFunctions(duffFuncBody, true); funcIt.hasNext();) {
			Function func = funcIt.next();
			if (!FunctionUtility.isDefaultFunctionName(func)) {
				continue;
			}
			try {
				func.setName(duffFunc.getName() + "_" + func.getEntryPoint(), SourceType.ANALYSIS);
				func.updateFunction(duffFunc.getCallingConventionName(), duffFunc.getReturn(),
					Arrays.asList(duffFunc.getParameters()),
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
				if (duffComment != null && !duffComment.isBlank()) {
					new SetCommentCmd(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, duffComment)
							.applyTo(program);
				}
			}
			catch (DuplicateNameException | InvalidInputException e) {
				log.appendMsg("Error updating duff functions");
				log.appendException(e);
			}
		}
	}

	private void configureDecompiler(DecompInterface decompiler) {
		decompiler.toggleCCode(false); //only need syntax tree
		decompiler.toggleSyntaxTree(true); // Produce syntax tree
		decompiler.setSimplificationStyle("normalize");
	}

	record HighFunctionAddresses(Address functionEntry, AddressSetView functionAddresses) {}

	/**
	 * Returns the addresses that a function occupies (as determined by the decompiler instead of
	 * the disassembler).
	 * 
	 * @param funcs list of functions
	 * @return map of function entry point and addresses for that function
	 */
	private Map<Address, AddressSetView> getFunctionActualRanges(List<Function> funcs) {
		DecompilerCallback<HighFunctionAddresses> callback =
			new DecompilerCallback<>(program, this::configureDecompiler) {
				@Override
				public HighFunctionAddresses process(DecompileResults results, TaskMonitor tMonitor)
						throws Exception {
					tMonitor.checkCancelled();
					if (results == null) {
						return null;
					}
					Function func = results.getFunction();
					HighFunction highFunc = results.getHighFunction();
					if (func == null || highFunc == null) {
						return null;
					}
					AddressSet funcAddrs = new AddressSet();
					for (PcodeBlockBasic bb : highFunc.getBasicBlocks()) {
						funcAddrs.add(bb.getStart(), bb.getStop());
					}
					return new HighFunctionAddresses(func.getEntryPoint(), funcAddrs);
				}
			};

		try {
			List<HighFunctionAddresses> funcAddresses =
				ParallelDecompiler.decompileFunctions(callback, funcs, monitor);
			Map<Address, AddressSetView> results = funcAddresses.stream()
					.collect(
						Collectors.toMap(hfa -> hfa.functionEntry, hfa -> hfa.functionAddresses));
			return results;
		}
		catch (Exception e) {
			Msg.error(this, "Error: could not decompile functions with ParallelDecompiler", e);
			return Map.of();
		}
		finally {
			callback.dispose();
		}
	}

}
