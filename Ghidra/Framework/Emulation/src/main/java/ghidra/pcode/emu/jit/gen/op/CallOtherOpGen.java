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
package ghidra.pcode.emu.jit.gen.op;

import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

import org.objectweb.asm.*;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.JitPassage.DecodedPcodeOp;
import ghidra.pcode.emu.jit.analysis.*;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.*;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.gen.var.VarGen.BlockTransition;
import ghidra.pcode.emu.jit.op.JitCallOtherDefOp;
import ghidra.pcode.emu.jit.op.JitCallOtherOpIf;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * The generator for a {@link JitCallOtherOpIf callother}.
 * 
 * <p>
 * The checks if Direct invocation is possible. If so, it emits code using
 * {@link #generateRunCodeUsingDirectStrategy(JitCodeGenerator, JitCallOtherOpIf, JitBlock, MethodVisitor)}.
 * If not, it emits code using
 * {@link #generateRunCodeUsingRetirementStrategy(JitCodeGenerator, PcodeOp, JitBlock, PcodeUseropDefinition, MethodVisitor)}.
 * Direct invocation is possible when the userop is {@link PcodeUseropDefinition#isFunctional()
 * functional} and all of its parameters and return type have a supported primitive type.
 * ({@code char} is not supported.) Regarding the invocation strategies, see
 * {@link JitDataFlowUseropLibrary} and note that the Inline strategy is already handled by this
 * point.
 * 
 * <p>
 * For the Standard strategy, we emit code to retire the program counter, decode context, and all
 * live variables. We then request a field to hold the userop and emit code to load it. We then emit
 * code to prepare its arguments and place them on the stack, namely the output varnode and an array
 * for the input varnodes. We request a field for each varnode and emit code to load them as needed.
 * For the array, we emit code to construct and fill it. We then emit code to invoke
 * {@link JitCompiledPassage#invokeUserop(PcodeUseropDefinition, Varnode, Varnode[])}. The userop
 * definition handles retrieving all of its inputs and writing the output, directly to the
 * {@link JitBytesPcodeExecutorState state}. Thus, we now need only to emit code to re-birth all the
 * live variables. If any errors occur, execution is interrupted as usual, and our state is
 * consistent.
 * 
 * <p>
 * For the Direct strategy, we wish to avoid retirement and re-birth, so we request an
 * {@link ExceptionHandler}. We request a field for the userop, just as in the Standard strategy,
 * but we emit code to invoke {@link PcodeUseropDefinition#getDefiningLibrary()} instead. We can use
 * {@link PcodeUseropDefinition#getJavaMethod()} <em>at generation time</em> to reflect its Java
 * definition. We then emit code to cast the library and load each of the operands onto the JVM
 * stack. We then emit the invocation of the Java method, guarded by the exception handler. We then
 * have to consider whether the userop has an output operand and whether its definition returns a
 * value. If both are true, we emit code to write the result. If neither is true, we're done. If a
 * result is returned, but no output operand is provided, we <em>must</em> still emit a {@link #POP
 * pop}.
 */
public enum CallOtherOpGen implements OpGen<JitCallOtherOpIf> {
	/** The generator singleton */
	GEN;

	/**
	 * Emit code to implement the Standard strategy (see the class documentation)
	 * 
	 * @param gen the code generator
	 * @param op the p-code op
	 * @param block the block containing the op
	 * @param userop the userop definition, wrapped by the {@link JitDataFlowUseropLibrary}
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	public static void generateRunCodeUsingRetirementStrategy(JitCodeGenerator gen, PcodeOp op,
			JitBlock block, PcodeUseropDefinition<?> userop, MethodVisitor rv) {
		/**
		 * This is about the simplest (laziest) approach we could take for the moment, but it should
		 * suffice, depending on the frequency of CALLOTHER executions. We immediately retire all
		 * variables, then invoke the userop as it would be by the p-code interpreter. It can access
		 * its variables in the usual fashion. Although not ideal, it can also feed the executor
		 * (interpreter) ops to execute --- they won't be jitted here. Then, we liven the variables
		 * back.
		 * 
		 * NOTE: The output variable should be "alive", so we need not store it into a local. It'll
		 * be made alive in the return block transition.
		 * 
		 * TODO: Implement direct invocation for functional userops. NOTE: Cannot avoid block
		 * retirement and re-birth unless I also do direct invocation. Otherwise, the parameters are
		 * read from the state instead of from the local variables.
		 */
		BlockTransition transition = VarGen.computeBlockTransition(gen, block, null);
		transition.generate(rv);

		gen.generateRetirePcCtx(() -> {
			rv.visitLdcInsn(gen.getAddressForOp(op).getOffset());
		}, gen.getExitContext(op), rv);

		// []
		rv.visitVarInsn(ALOAD, 0);
		// [this]
		gen.requestFieldForUserop(userop).generateLoadCode(gen, rv);
		// [this,userop]

		if (op.getOutput() == null) {
			rv.visitInsn(ACONST_NULL);
		}
		else {
			gen.requestStaticFieldForVarnode(op.getOutput()).generateLoadCode(gen, rv);
		}
		// [this,userop,outVn]

		rv.visitLdcInsn(op.getNumInputs() - 1);
		rv.visitTypeInsn(ANEWARRAY, NAME_VARNODE);
		// [this,userop,outVn,inVns:ARR]
		for (int i = 1; i < op.getNumInputs(); i++) {
			// [this,userop,outVn,inVns:ARR]
			rv.visitInsn(DUP);
			// [this,userop,outVn,inVns:ARR,inVns:ARR]
			rv.visitLdcInsn(i - 1);
			// [this,userop,outVn,inVns:ARR,inVns:ARR,index]
			// Yes, including constants :/
			Varnode input = op.getInput(i);
			gen.requestStaticFieldForVarnode(input).generateLoadCode(gen, rv);
			// [this,userop,outVn,inVns:ARR,inVns:ARR,index,inVn]
			rv.visitInsn(AASTORE);
			// [this,userop,outVn,inVns:ARR]
		}
		// [this,userop,outVn,inVns:ARR]

		rv.visitMethodInsn(INVOKEINTERFACE, NAME_JIT_COMPILED_PASSAGE, "invokeUserop",
			MDESC_JIT_COMPILED_PASSAGE__INVOKE_USEROP, true);

		transition.generateInv(rv);
	}

	/**
	 * Emit code to implement the Direct strategy (see the class documentation)
	 * 
	 * @param gen the code generator
	 * @param op the p-code op use-def node
	 * @param block the block containing the op
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	public static void generateRunCodeUsingDirectStrategy(JitCodeGenerator gen,
			JitCallOtherOpIf op, JitBlock block, MethodVisitor rv) {
		FieldForUserop useropField = gen.requestFieldForUserop(op.userop());

		// Set<Varnode> live = gen.vsm.getLiveVars(block);
		/**
		 * NOTE: It doesn't matter if there are live variables. We still have to "retire" the
		 * program counter and contextreg if the userop throws an exception.
		 */
		final Label tryStart = new Label();
		final Label tryEnd = new Label();
		rv.visitTryCatchBlock(tryStart, tryEnd,
			gen.requestExceptionHandler((DecodedPcodeOp) op.op(), block).label(), NAME_THROWABLE);

		// []
		useropField.generateLoadCode(gen, rv);
		// [userop]
		rv.visitMethodInsn(INVOKEINTERFACE, NAME_PCODE_USEROP_DEFINITION, "getDefiningLibrary",
			MDESC_PCODE_USEROP_DEFINITION__GET_DEFINING_LIBRARY, true);
		// [library:PcodeUseropLibrary]
		Method method = op.userop().getJavaMethod();
		String owningLibName = Type.getInternalName(method.getDeclaringClass());
		rv.visitTypeInsn(CHECKCAST, owningLibName);
		// [library:OWNING_TYPE]
		Parameter[] parameters = method.getParameters();
		for (int i = 0; i < op.args().size(); i++) {
			JitVal arg = op.args().get(i);
			Parameter p = parameters[i];

			JitType type = gen.generateValReadCode(arg, JitTypeBehavior.ANY);
			if (p.getType() == boolean.class) {
				TypeConversions.generateIntToBool(type, rv);
			}
			else {
				TypeConversions.generate(gen, type, JitType.forJavaType(p.getType()), rv);
			}
		}
		// [library,params...]
		rv.visitLabel(tryStart);
		rv.visitMethodInsn(INVOKEVIRTUAL, owningLibName, method.getName(),
			Type.getMethodDescriptor(method), false);
		// [return?]
		rv.visitLabel(tryEnd);
		if (op instanceof JitCallOtherDefOp defOp) {
			gen.generateVarWriteCode(defOp.out(), JitType.forJavaType(method.getReturnType()));
		}
		else if (method.getReturnType() != void.class) {
			TypeConversions.generatePop(JitType.forJavaType(method.getReturnType()), rv);
		}
	}

	/**
	 * Check if the Direct invocation strategy is applicable (see class documentation)
	 * 
	 * @param op the p-code op use-def node
	 * @return true if applicable
	 */
	public static boolean canDoDirectInvocation(JitCallOtherOpIf op) {
		if (!op.userop().isFunctional()) {
			return false;
		}

		for (JitTypeBehavior type : op.inputTypes()) {
			if (type == JitTypeBehavior.ANY) {
				return false;
			}
		}
		if (op instanceof JitCallOtherDefOp defOp) {
			if (defOp.type() == JitTypeBehavior.ANY) {
				return false;
			}
		}

		return true;
	}

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitCallOtherOpIf op, JitBlock block,
			MethodVisitor rv) {
		if (canDoDirectInvocation(op)) {
			generateRunCodeUsingDirectStrategy(gen, op, block, rv);
		}
		else {
			generateRunCodeUsingRetirementStrategy(gen, op.op(), block, op.userop(), rv);
		}
	}
}
