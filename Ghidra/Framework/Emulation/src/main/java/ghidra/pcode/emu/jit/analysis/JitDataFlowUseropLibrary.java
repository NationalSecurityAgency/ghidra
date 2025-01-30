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
package ghidra.pcode.emu.jit.analysis;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.decode.DecoderUseropLibrary;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.JitOutVar;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary.PcodeUserop;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A wrapper around a userop library that places {@link PcodeOp#CALLOTHER callother} ops into the
 * use-def graph
 * 
 * <p>
 * This is the library provided to
 * {@link JitDataFlowExecutor#execute(PcodeProgram, PcodeUseropLibrary)} to cooperate with in the
 * population of the use-def graph. The Sleigh compiler is very permissive when it comes to userop
 * invocations. Notably, there's no way to declare the "prototype" or "signature" of the userop.
 * Invocations can have any number of input operands and an optional output operand. Because the
 * use-def graph takes careful notice of variables and their definiting ops, there are two possible
 * op nodes: {@link JitCallOtherOp} when no output operand is given and {@link JitCallOtherDefOp}
 * when an output operand is given.
 * 
 * <p>
 * We employ several different strategies to handle a p-code userop:
 * 
 * <ul>
 * <li><b>Standard</b>: Invocation of the userop in the same fashion as the interpreted p-code
 * emulator. Any live variables have to be written into the {@link JitBytesPcodeExecutorState state}
 * before the invocation and the read back out afterward. If the userop accesses the state directly,
 * we must use this strategy. Most userops whose implementations precede the introduction of JIT
 * acceleration can be supported with this strategy, so long as they don't manipulate the
 * emulator/executor directly is some unsupported way.</li>
 * <li><b>Inlining</b>: The inclusion of the userop's p-code directly at its call site, replacing
 * the {@link PcodeOp#CALLOTHER} op. This is implemented in the decoder by
 * {@link DecoderUseropLibrary}. This strategy is only applicable to userops defined using Sleigh
 * and/or p-code.</li>
 * <li><b>Direct</b>: The direct invocation of the userop's defining Java method in the generated
 * JVM bytecode. This is applicable when the method's parameters and return type are primitives that
 * each map to a {@link JitTypeBehavior}. The input values can be passed directly in, which works
 * well when the inputs are registers or uniques allocated in JVM locals. The return value can be
 * handled similarly.</li>
 * </ul>
 * 
 * <p>
 * The default strategy for all userops is Standard. Implementors should set the attributes of
 * {@link PcodeUserop} and adjust the parameters of the userop's method accordingly. To allow
 * inlining, set {@link PcodeUserop#canInline() canInline}. To allow direct invocation, set
 * {@link PcodeUserop#functional()} and ensure all the parameter types and return type are
 * supported. Supported types include primitives other than {@code char}. The return type may be
 * {@code void}. No matter the strategy, userops may be subject to removal by the
 * {@link JitOpUseModel}. To permit removal, clear {@link PcodeUserop#hasSideEffects()}. The default
 * prevents removal. For the inline strategy, each op from the inlined userop is analyzed
 * separately, so the userop could be partially culled. An inlined userop cannot have side effects,
 * and so the attribute is ignored.
 */
public class JitDataFlowUseropLibrary implements PcodeUseropLibrary<JitVal> {

	/**
	 * The wrapper of a specific userop definition
	 */
	protected class WrappedUseropDefinition implements PcodeUseropDefinition<JitVal> {
		private final PcodeUseropDefinition<Object> decOp;

		public WrappedUseropDefinition(PcodeUseropDefinition<Object> decOp) {
			this.decOp = decOp;
		}

		@Override
		public String getName() {
			return decOp.getName();
		}

		@Override
		public int getInputCount() {
			return decOp.getInputCount();
		}

		@Override
		public void execute(PcodeExecutor<JitVal> executor, PcodeUseropLibrary<JitVal> library,
				Varnode outVar, List<Varnode> inVars) {
			throw new AssertionError();
		}

		/**
		 * If the number of arguments matches the userop's Java method, map each argument value to
		 * the type behavior for its corresponding parameter.
		 * 
		 * <p>
		 * This is used by the {@link JitTypeModel} to assign types to JVM locals in order to reduce
		 * the number of type casts. In the case of direct invocation, this enters type information
		 * from the userop's Java definition into the analysis.
		 * 
		 * <p>
		 * If the parameter count doesn't match, we just map the arguments to
		 * {@link JitTypeBehavior#ANY} and let the error surface at run time. We need not throw the
		 * exception until/unless the invocation is actually executed. Similarly, if any parameter's
		 * type is not supported, or the userop cannot be invoked directly, we just map all
		 * arguments to {@link JitTypeBehavior#ANY}, because the generator will apply standard
		 * invocation, which does not benefit from type analysis.
		 * 
		 * @param inVals the input arguments
		 * @return the map from argument value (SSA variable) to parameter type behavior
		 */
		private List<JitTypeBehavior> getInputTypes(List<JitVal> inVals) {
			int inputCount = getInputCount();
			if (inputCount != inVals.size()) { // includes inputCount == -1 (variadic)
				return JitDataFlowModel.allAny(inVals);
			}
			Method method = decOp.getJavaMethod();
			if (method == null) {
				return JitDataFlowModel.allAny(inVals);
			}
			List<JitTypeBehavior> result = new ArrayList<>();
			Parameter[] parameters = method.getParameters();
			for (int i = 0; i < inVals.size(); i++) {
				Parameter p = parameters[i];
				JitTypeBehavior type = JitTypeBehavior.forJavaType(p.getType());
				if (type == null) {
					return JitDataFlowModel.allAny(inVals);
				}
				result.add(type);
			}
			return Collections.unmodifiableList(result);
		}

		/**
		 * Get the type behavior from the userop's Java method
		 * 
		 * <p>
		 * If the userop is not backed by a Java method, or its return type is not supported, this
		 * return {@link JitTypeBehavior#ANY}.
		 * 
		 * @return the type behavior
		 */
		private JitTypeBehavior getReturnType() {
			Method method = decOp.getJavaMethod();
			if (method == null) {
				return JitTypeBehavior.ANY;
			}
			return JitTypeBehavior.forJavaType(method.getReturnType());
		}

		/**
		 * {@inheritDoc}
		 * 
		 * <p>
		 * This "execution" is part of the intra-block analysis. This is the analytic interpretation
		 * of the invocation, not the actual run time invocation. This derives type information
		 * about the userop from the Java method and selects the approparite {@link JitCallOtherOpIf
		 * callother} op to enter into the use-def graph. If an output operand is given, then this
		 * generates an output notes defined by a {@link JitCallOtherDefOp}. Otherwise, it generates
		 * a (sink) {@link JitCallOtherOp}.
		 * 
		 * @implNote When inlining a userop, the decoder leaves the original callother op in place.
		 *           This is for branch bookkeeping. Thus, we ask the decoder-wrapped version of the
		 *           userop if it was inlined. If so, we enter a {@link JitNopOp nop} node into the
		 *           use-def graph. The node will still contain the original callother op, but the
		 *           generator will not emit any code.
		 * @implNote <b>TODO</b>: Maybe float types shouldn't be size cast as ints and then bitcast
		 *           to the requested type. Either that, or we need to develop an overloading system
		 *           for userops, or to require the user to be very careful about which to invoke
		 *           for what (float) operand sizes. <b>TODO</b>: I don't know what the actual
		 *           behavior is here. We should add test cases for this.
		 * @implNote <b>TODO</b>: I think userop libraries may need to be able to hook this point.
		 *           Not sure to what extent we should allow them control of code generation. But
		 *           consider a syscall library. It might like to try to concretize, e.g., RAX, and
		 *           just hard code the invoked userop in the generated code.
		 */
		@Override
		public void execute(PcodeExecutor<JitVal> executor, PcodeUseropLibrary<JitVal> library,
				PcodeOp op) {
			if (decOp.canInlinePcode()) {
				dfm.notifyOp(new JitNopOp(op));
				return;
			}
			JitDataFlowState state = (JitDataFlowState) executor.getState();
			List<JitVal> inVals = Stream.of(op.getInputs())
					.skip(1)
					.map(inVn -> state.getVar(inVn, executor.getReason()))
					.toList();
			List<JitTypeBehavior> inTypes = getInputTypes(inVals);
			Varnode outVn = op.getOutput();
			if (outVn == null) {
				dfm.notifyOp(new JitCallOtherOp(op, decOp, inVals, inTypes, state.captureState()));
			}
			else {
				JitOutVar out = dfm.generateOutVar(outVn);
				dfm.notifyOp(new JitCallOtherDefOp(op, out, getReturnType(), decOp, inVals, inTypes,
					state.captureState()));
				state.setVar(outVn, out);
			}
		}

		@Override
		public boolean isFunctional() {
			return decOp.isFunctional();
		}

		@Override
		public boolean hasSideEffects() {
			return decOp.hasSideEffects();
		}

		@Override
		public boolean canInlinePcode() {
			return decOp.canInlinePcode();
		}

		@Override
		public Method getJavaMethod() {
			return decOp.getJavaMethod();
		}

		@Override
		public PcodeUseropLibrary<?> getDefiningLibrary() {
			return decOp.getDefiningLibrary();
		}
	}

	private final JitDataFlowModel dfm;

	private final Map<String, PcodeUseropDefinition<JitVal>> userops;

	/**
	 * Construct a wrapper library
	 * 
	 * @param context the context from which the decoder's userop wrapper library is retrieved
	 * @param dfm the data flow model whose use-def graph to populate.
	 * @implNote Each time this is constructed, it has to traverse the wrapped userop library and
	 *           create a wrapper for each individual userop. For a large library, this could get
	 *           expensive, and it currently must happen for every passage compiled. Part of the
	 *           cause for this requirement is the reference to the data flow mode used by each
	 *           userop wrapper.
	 */
	public JitDataFlowUseropLibrary(JitAnalysisContext context, JitDataFlowModel dfm) {
		this.dfm = dfm;
		this.userops = context.getPassage()
				.getDecodeLibrary()
				.getUserops()
				.values()
				.stream()
				.map(WrappedUseropDefinition::new)
				.collect(Collectors.toUnmodifiableMap(d -> d.getName(), d -> d));
	}

	@Override
	public Map<String, PcodeUseropDefinition<JitVal>> getUserops() {
		return userops;
	}
}
