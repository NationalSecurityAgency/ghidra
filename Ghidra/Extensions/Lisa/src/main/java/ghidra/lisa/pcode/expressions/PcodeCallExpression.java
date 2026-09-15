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
package ghidra.lisa.pcode.expressions;

import java.util.HashSet;
import java.util.Set;

import ghidra.lisa.pcode.contexts.CallContext;
import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.analysis.value.ValueDomain;
import it.unive.lisa.interprocedural.InterproceduralAnalysis;
import it.unive.lisa.program.cfg.CFG;
import it.unive.lisa.program.cfg.statement.Expression;
import it.unive.lisa.program.cfg.statement.call.UnresolvedCall;
import it.unive.lisa.symbolic.value.Variable;

public class PcodeCallExpression extends UnresolvedCall {

	private Function function;
	private Set<Varnode> unaffected = new HashSet<>();
	private Set<Varnode> killedByCall = new HashSet<>();

	public PcodeCallExpression(
			CFG cfg,
			CallContext ctx,
			Expression expression) {
		super(cfg, ctx.location(), ctx.type(), null, ctx.getCalleeName(), expression);
		function = ctx.function();
		if (function != null) {
			PrototypeModel callingConvention = function.getCallingConvention();
			if (callingConvention != null) {
				Varnode[] unaffectedList = callingConvention.getUnaffectedList();
				for (Varnode varnode : unaffectedList) {
					unaffected.add(varnode);
				}
				Varnode[] killedByCallList = callingConvention.getKilledByCallList();
				for (Varnode varnode : killedByCallList) {
					killedByCall.add(varnode);
				}
			}
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public <A extends AbstractState<A>> AnalysisState<A> forwardSemantics(
			AnalysisState<A> entryState,
			InterproceduralAnalysis<A> interprocedural,
			StatementStore<A> expressions)
			throws SemanticException {

		// TODO: This triggers the processing of the callee, but we effectively clears the state.
		//  We're using the slightly-sanitized entry state instead.  Quite possible, the return
		//  value from the function is being dropped here - not clear how this works.
		super.forwardSemantics(entryState, interprocedural, expressions);

		if (unaffected.isEmpty()) {
			return entryState;
		}
		if (entryState.getState() instanceof SimpleAbstractState sas) {
			ValueDomain<?> vDomain = sas.getValueState();
			if (vDomain instanceof ValueEnvironment vEnv) {
				if (vEnv.function == null) {
					return entryState;
				}
				for (Object key : vEnv.function.keySet()) {
					Object val = vEnv.function.get(key);
					if (key instanceof Variable var && val instanceof Lattice lat) {
						if (var.getCodeLocation() instanceof PcodeLocation loc) {
							Varnode output = loc.op.getOutput();
							if (output != null &&
								output.getAddress().getAddressSpace().isRegisterSpace()) {
								if (unaffected.contains(output)) {
									continue;
								}
								if (killedByCall.contains(output)) {
									vEnv.function.put(key, lat.top());
								}
							}
						}
					}
				}
			}
		}
		return entryState;
	}
}
