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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Relabels {@code jral5 lp} / {@code jral Rt, lp} / {@code jr5 lp} as returns when
 * {@code lp} has not been written within the function.  NDS32 compilers occasionally
 * end a function with {@code jral5 lp} rather than {@code ret5 lp}; the sleigh emits
 * a {@code call [lp]}, so without a flow override Ghidra treats it as a computed call
 * with fall-through into the next function.
 */
public class NDS32JralLpReturnAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "NDS32 jral5 lp -> return";
	private static final String DESCRIPTION =
		"Marks `jral5 lp` / `jral Rt, lp` / `jr5 lp` as returns when " +
			"`lp` has not been clobbered earlier in the function.";
	private static final String PROCESSOR_NAME = "NDS32";

	public NDS32JralLpReturnAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Register lp = program.getLanguage().getRegister("lp");
		if (lp == null) {
			log.appendMsg(NAME, "lp register not found; skipping.");
			return false;
		}
		FunctionManager fm = program.getFunctionManager();
		int converted = 0;

		FunctionIterator funcs = (set != null && !set.isEmpty())
			? fm.getFunctions(set, true)
			: fm.getFunctions(true);
		while (funcs.hasNext()) {
			monitor.checkCancelled();
			Function f = funcs.next();
			if (f.isThunk()) {
				continue;
			}
			converted += processFunction(program, f, lp);
		}
		if (converted > 0) {
			Msg.info(this, NAME + ": Re-labelled " + converted + " jral/jr lp site(s) as RETURN.");
		}
		return converted > 0;
	}

	/**
	 * Apply FlowOverride.RETURN to candidate jral/jr-via-lp instructions in {@code f}
	 * when lp is provably pristine (no non-candidate, non-pop25 writer in the body).
	 */
	private int processFunction(Program program, Function f, Register lp) {
		Listing listing = program.getListing();
		boolean lpClobbered = false;
		List<Instruction> candidates = new ArrayList<>();
		for (Instruction i : (Iterable<Instruction>) () ->
				listing.getInstructions(f.getBody(), true)) {
			if (isLpReturnCandidate(i, lp)) {
				candidates.add(i);
				continue;
			}
			if (writesLp(i, lp) && !isLpRestore(i)) {
				lpClobbered = true;
			}
		}
		if (candidates.isEmpty() || lpClobbered) {
			return 0;
		}
		int n = 0;
		for (Instruction i : candidates) {
			if (i.getFlowOverride() == FlowOverride.RETURN) {
				continue;
			}
			i.setFlowOverride(FlowOverride.RETURN);
			n++;
		}
		return n;
	}

	private static boolean isLpReturnCandidate(Instruction i, Register lp) {
		String mn = i.getMnemonicString();
		if ("jral5".equals(mn) || "jr5".equals(mn)) {
			Object[] ops = i.getOpObjects(0);
			return ops.length == 1 && ops[0] == lp;
		}
		if ("jral".equals(mn)) {
			Object[] ops = i.getOpObjects(1);
			return ops.length == 1 && ops[0] == lp;
		}
		return false;
	}

	private static boolean writesLp(Instruction i, Register lp) {
		Object[] outs = i.getResultObjects();
		for (Object o : outs) {
			if (o == lp) {
				return true;
			}
		}
		return false;
	}

	// pop25 restores lp from the push25 frame, so the value at the jr point equals
	// the function-entry value -- treat as a no-op write for the pristine check.
	private static boolean isLpRestore(Instruction i) {
		return "pop25".equals(i.getMnemonicString());
	}
}
