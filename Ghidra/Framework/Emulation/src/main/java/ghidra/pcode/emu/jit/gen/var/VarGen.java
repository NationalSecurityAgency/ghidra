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
package ghidra.pcode.emu.jit.gen.var;

import static ghidra.pcode.emu.jit.gen.GenConsts.BLOCK_SIZE;

import java.util.LinkedHashSet;
import java.util.Set;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.analysis.*;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.JvmLocal;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.op.CBranchOpGen;
import ghidra.pcode.emu.jit.gen.op.CallOtherOpGen;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypedAccessGen;
import ghidra.pcode.emu.jit.var.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.Varnode;

/**
 * The bytecode generator for a specific use-def variable (operand) access
 * 
 * <p>
 * For a table of value types, their use-def types, their generator classes, and relevant read/write
 * opcodes, see {@link JitVal}. This interface is an extension of the {@link JitVal} interface that
 * allows writing. The only non-{@link JitVar} {@link JitVal} is {@link JitConstVal}. As such, most
 * of the variable-access logic is actually contained here.
 * 
 * @param <V> the class of p-code variable node in the use-def graph
 * @see ValGen
 */
public interface VarGen<V extends JitVar> extends ValGen<V> {
	/**
	 * Lookup the generator for a given p-code variable use-def node
	 * 
	 * @param <V> the class of the variable
	 * @param v the {@link JitVar} whose generator to look up
	 * @return the generator
	 */
	@SuppressWarnings("unchecked")
	static <V extends JitVar> VarGen<V> lookup(V v) {
		return (VarGen<V>) switch (v) {
			case JitIndirectMemoryVar imv -> throw new AssertionError();
			case JitDirectMemoryVar dmv -> DirectMemoryVarGen.GEN;
			case JitInputVar iv -> InputVarGen.GEN;
			case JitMissingVar mv -> MissingVarGen.GEN;
			case JitMemoryOutVar mov -> MemoryOutVarGen.GEN;
			case JitLocalOutVar lov -> LocalOutVarGen.GEN;
			default -> throw new AssertionError();
		};
	}

	/**
	 * Emit bytecode necessary to support access to the given varnode
	 * 
	 * <p>
	 * This applies to all varnode types: {@code memory}, {@code unique}, and {@code register}, but
	 * not {@code const}. For memory varnodes, we need to pre-fetch the byte arrays backing their
	 * pages, so we can access them at the translation site. For unique and register varnodes, we
	 * also need to pre-fetch the byte arrays backing their pages, so we can birth and retire them
	 * at {@link BlockTransition transitions}. Technically, the methods for generating the read and
	 * write code will already call {@link JitCodeGenerator#requestFieldForArrDirect(Address)};
	 * however, we'd like to ensure the fields appear in the classfile in a comprehensible order, so
	 * we have the generator iterate the variables in address order and invoke this method, where we
	 * make the request first.
	 * 
	 * @param gen the code generator
	 * @param vn the varnode
	 */
	static void generateValInitCode(JitCodeGenerator gen, Varnode vn) {
		long start = vn.getOffset();
		long endIncl = start + vn.getSize() - 1;
		long startBlock = start / BLOCK_SIZE * BLOCK_SIZE;
		long endBlockIncl = endIncl / BLOCK_SIZE * BLOCK_SIZE;
		// Use != to allow wrap-around.
		for (long block = startBlock; block != endBlockIncl + BLOCK_SIZE; block += BLOCK_SIZE) {
			gen.requestFieldForArrDirect(vn.getAddress().getNewAddress(block));
		}
	}

	/**
	 * Emit bytecode that loads the given varnode with the given p-code type from the
	 * {@link JitBytesPcodeExecutorState state} onto the JVM stack.
	 * 
	 * <p>
	 * This is used for direct memory accesses and for register/unique scope transitions. The JVM
	 * type of the stack variable is determined by the {@code type} argument.
	 * 
	 * @param gen the code generator
	 * @param type the p-code type of the variable
	 * @param vn the varnode to read from the state
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	static void generateValReadCodeDirect(JitCodeGenerator gen, JitType type, Varnode vn,
			MethodVisitor rv) {
		TypedAccessGen.lookupReader(gen.getAnalysisContext().getEndian(), type)
				.generateCode(gen, vn, rv);
	}

	/**
	 * Emit bytecode that loads the given use-def variable from the
	 * {@link JitBytesPcodeExecutorState state} onto the JVM stack.
	 * 
	 * <p>
	 * The actual type is determined by resolving the {@code typeReq} argument against the given
	 * variable. Since the variable is being loaded directly from the state, which is just raw
	 * bytes/bits, we ignore the "assigned" type and convert directly the type required by the
	 * operand.
	 * 
	 * @param gen the code generator
	 * @param v the use-def variable node
	 * @param typeReq the type (behavior) required by the operand.
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 * @return the resulting p-code type (which also describes the JVM type) of the value on the JVM
	 *         stack
	 */
	static JitType generateValReadCodeDirect(JitCodeGenerator gen, JitVarnodeVar v,
			JitTypeBehavior typeReq, MethodVisitor rv) {
		JitType type = typeReq.resolve(gen.getTypeModel().typeOf(v));
		generateValReadCodeDirect(gen, type, v.varnode(), rv);
		return type;
	}

	/**
	 * Emit bytecode that writes the given varnode with the given p-code type in the
	 * {@link JitBytesPcodeExecutorState state} from the JVM stack.
	 * 
	 * <p>
	 * This is used for direct memory accesses and for register/unique scope transitions. The
	 * expected JVM type of the stack variable is described by the {@code type} argument.
	 * 
	 * @param gen the code generator
	 * @param type the p-code type of the variable
	 * @param vn the varnode to write in the state
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	static void generateValWriteCodeDirect(JitCodeGenerator gen, JitType type, Varnode vn,
			MethodVisitor rv) {
		TypedAccessGen.lookupWriter(gen.getAnalysisContext().getEndian(), type)
				.generateCode(gen, vn, rv);
	}

	/**
	 * Emit bytecode that writes the given use-def variable in the {@link JitBytesPcodeExecutorState
	 * state} from the JVM stack.
	 * 
	 * <p>
	 * The expected type is given by the {@code type} argument. Since the variable is being written
	 * directly into the state, which is just raw bytes/bits, we ignore the "assigned" type and
	 * convert using the given type instead.
	 * 
	 * @param gen the code generator
	 * @param v the use-def variable node
	 * @param type the p-code type of the value on the stack, as required by the operand
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	static void generateValWriteCodeDirect(JitCodeGenerator gen, JitVarnodeVar v,
			JitType type, MethodVisitor rv) {
		generateValWriteCodeDirect(gen, type, v.varnode(), rv);
	}

	/**
	 * For block transitions: emit bytecode that births (loads) variables from the
	 * {@link JitBytesPcodeExecutorState state} into their allocated JVM locals.
	 * 
	 * @param gen the code generator
	 * @param toBirth the set of varnodes to load
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	static void generateBirthCode(JitCodeGenerator gen, Set<Varnode> toBirth, MethodVisitor rv) {
		for (Varnode vn : toBirth) {
			for (JvmLocal local : gen.getAllocationModel().localsForVn(vn)) {
				local.generateBirthCode(gen, rv);
			}
		}
	}

	/**
	 * For block transitions: emit bytecode the retires (writes) variables into the
	 * {@link JitBytesPcodeExecutorState state} from their allocated JVM locals.
	 * 
	 * @param gen the code generator
	 * @param toRetire the set of varnodes to write
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	static void generateRetireCode(JitCodeGenerator gen, Set<Varnode> toRetire, MethodVisitor rv) {
		for (Varnode vn : toRetire) {
			for (JvmLocal local : gen.getAllocationModel().localsForVn(vn)) {
				local.generateRetireCode(gen, rv);
			}
		}
	}

	/**
	 * A means to emit bytecode on transitions between {@link JitBlock blocks}
	 * 
	 * @param gen the code generator
	 * @param toRetire the varnodes to retire on the transition
	 * @param toBirth the varnodes to birth on the transition
	 */
	public record BlockTransition(JitCodeGenerator gen, Set<Varnode> toRetire,
			Set<Varnode> toBirth) {
		/**
		 * Construct a "nop" or blank transition.
		 * 
		 * <p>
		 * The transition is mutable, so it's common to create one in this fashion and then populate
		 * it.
		 * 
		 * @param gen the code generator
		 */
		public BlockTransition(JitCodeGenerator gen) {
			this(gen, new LinkedHashSet<>(), new LinkedHashSet<>());
		}

		/**
		 * Check if a transition is actually needed.
		 * 
		 * <p>
		 * When a transition is not needed, some smaller control-flow constructs (e.g., in
		 * {@link CBranchOpGen}) can be averted.
		 * 
		 * @return true if bytecode must be emitted
		 */
		public boolean needed() {
			return !toRetire.isEmpty() || !toBirth().isEmpty();
		}

		/**
		 * Emit bytecode for the transition
		 * 
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		public void generate(MethodVisitor rv) {
			generateRetireCode(gen, toRetire, rv);
			generateBirthCode(gen, toBirth, rv);
		}

		/**
		 * Emit bytecode for the reverse transition
		 * 
		 * <p>
		 * Sometimes "transitions" are used around hazards, notably {@link CallOtherOpGen}. This
		 * method is used after the hazard to restore the live variables in scope.
		 * ({@link #generate(MethodVisitor)} is used before the hazard.) Variables that were retired
		 * and re-birthed here. There should not have been any variables birthed going into the
		 * hazard.
		 * 
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		public void generateInv(MethodVisitor rv) {
			generateRetireCode(gen, toBirth, rv);
			generateBirthCode(gen, toRetire, rv);
		}
	}

	/**
	 * Compute the retired and birthed varnodes for a transition between the given blocks.
	 * 
	 * <p>
	 * Either block may be {@code null} to indicate entering or leaving the passage. Additionally,
	 * the {@code to} block should be {@code null} when generating transitions around a hazard.
	 * 
	 * @param gen the code generator
	 * @param from the block control flow is leaving (whether by branch or fall through)
	 * @param to the block control flow is entering
	 * @return the means of generating bytecode at the transition
	 */
	static BlockTransition computeBlockTransition(JitCodeGenerator gen, JitBlock from,
			JitBlock to) {
		JitVarScopeModel scopeModel = gen.getVariableScopeModel();
		Set<Varnode> liveFrom = from == null ? Set.of() : scopeModel.getLiveVars(from);
		Set<Varnode> liveTo = to == null ? Set.of() : scopeModel.getLiveVars(to);
		BlockTransition result = new BlockTransition(gen);

		result.toRetire.addAll(liveFrom);
		result.toRetire.removeAll(liveTo);

		result.toBirth.addAll(liveTo);
		result.toBirth.removeAll(liveFrom);

		return result;
	}

	/**
	 * Write a value from the stack into the given variable
	 * 
	 * @param gen the code generator
	 * @param v the variable to write
	 * @param type the p-code type (which also determines the expected JVM type) of the value on the
	 *            stack
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	void generateVarWriteCode(JitCodeGenerator gen, V v, JitType type, MethodVisitor rv);
}
