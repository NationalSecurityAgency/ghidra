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

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.alloc.JvmLocal;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.analysis.JitVarScopeModel;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.access.AccessGen;
import ghidra.pcode.emu.jit.gen.op.CBranchOpGen;
import ghidra.pcode.emu.jit.gen.op.CallOtherOpGen;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.BPrim;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
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
			case JitDirectMemoryVar dmv -> WholeDirectMemoryVarGen.GEN;
			case JitInputVar iv -> WholeInputVarGen.GEN;
			case JitMissingVar mv -> MissingVarGen.GEN;
			case JitMemoryOutVar mov -> WholeMemoryOutVarGen.GEN;
			case JitLocalOutVar lov -> WholeLocalOutVarGen.GEN;
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
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param gen the code generator
	 * @param vn the varnode
	 * @return the emitter with ...
	 */
	static <N extends Next> Emitter<N> genVarnodeInit(Emitter<N> em, JitCodeGenerator<?> gen,
			Varnode vn) {
		long start = vn.getOffset();
		long endIncl = start + vn.getSize() - 1;
		long startBlock = start / BLOCK_SIZE * BLOCK_SIZE;
		long endBlockIncl = endIncl / BLOCK_SIZE * BLOCK_SIZE;
		// Use != instead of < to allow wrap-around.
		for (long block = startBlock; block != endBlockIncl + BLOCK_SIZE; block += BLOCK_SIZE) {
			gen.requestFieldForArrDirect(vn.getAddress().getNewAddress(block));
		}

		return em;
	}

	/**
	 * Emit bytecode that loads the given varnode with the given p-code type from the
	 * {@link JitBytesPcodeExecutorState state} onto the stack.
	 * 
	 * <p>
	 * This is used for direct memory accesses and for register/unique scope transitions. The JVM
	 * type of the operand is determined by the {@code type} argument.
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param type the p-code type of the variable
	 * @param vn the varnode to read from the state
	 * @return the emitter with ..., result
	 */
	static <THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N extends Next> Emitter<Ent<N, T>> genReadValDirectToStack(Emitter<N> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JT type, Varnode vn) {
		return AccessGen.lookupSimple(gen.getAnalysisContext().getEndian(), type)
				.genReadToStack(em, localThis, gen, vn);
	}

	/**
	 * Emit bytecode that writes the given varnode with the given p-code type in the
	 * {@link JitBytesPcodeExecutorState state} from a stack operand.
	 * 
	 * <p>
	 * This is used for direct memory accesses and for register/unique scope transitions. The
	 * expected JVM type of the stack variable is described by the {@code type} argument.
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param type the type of the operand on the stack
	 * @param vn the varnode to write in the state
	 * @return the emitter with ...
	 */
	static <THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N1 extends Next,
		N0 extends Ent<N1, T>> Emitter<N1> genWriteValDirectFromStack(Emitter<N0> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JT type, Varnode vn) {
		return AccessGen.lookupSimple(gen.getAnalysisContext().getEndian(), type)
				.genWriteFromStack(em, localThis, gen, vn);
	}

	/**
	 * Emit bytecode that writes the given use-def variable in the {@link JitBytesPcodeExecutorState
	 * state} from a stack operand.
	 * 
	 * <p>
	 * The expected type is given by the {@code type} argument. Since the variable is being written
	 * directly into the state, which is just raw bytes/bits, we ignore the "assigned" type and
	 * convert using the given type instead.
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param type the type of the operand on the stack
	 * @param v the use-def variable node
	 * @return the emitter with ...
	 */
	static <THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N1 extends Next,
		N0 extends Ent<N1, T>> Emitter<N1> genWriteValDirectFromStack(Emitter<N0> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JT type, JitVarnodeVar v) {
		return genWriteValDirectFromStack(em, localThis, gen, type, v.varnode());
	}

	/**
	 * For block transitions: emit bytecode that births (loads) variables from the
	 * {@link JitBytesPcodeExecutorState state} into their allocated JVM locals.
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param toBirth the set of varnodes to load
	 * @return the emitter with ...
	 */
	static <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genBirth(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, Set<Varnode> toBirth) {
		for (Varnode vn : toBirth) {
			for (JvmLocal<?, ?> local : gen.getAllocationModel().localsForVn(vn)) {
				em = local.genBirthCode(em, localThis, gen);
			}
		}
		return em;
	}

	/**
	 * For block transitions: emit bytecode the retires (writes) variables into the
	 * {@link JitBytesPcodeExecutorState state} from their allocated JVM locals.
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param toRetire the set of varnodes to write
	 * @return the emitter with ...
	 */
	static <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genRetire(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, Set<Varnode> toRetire) {
		for (Varnode vn : toRetire) {
			for (JvmLocal<?, ?> local : gen.getAllocationModel().localsForVn(vn)) {
				em = local.genRetireCode(em, localThis, gen);
			}
		}
		return em;
	}

	/**
	 * A means to emit bytecode on transitions between {@link JitBlock blocks}
	 * 
	 * @param <THIS> the type of the generated class
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param toRetire the varnodes to retire on the transition
	 * @param toBirth the varnodes to birth on the transition
	 */
	public record BlockTransition<THIS extends JitCompiledPassage>(Local<TRef<THIS>> localThis,
			JitCodeGenerator<THIS> gen, Set<Varnode> toRetire, Set<Varnode> toBirth) {
		/**
		 * Construct a "nop" or blank transition.
		 * 
		 * <p>
		 * The transition is mutable, so it's common to create one in this fashion and then populate
		 * it.
		 * 
		 * @param localThis a handle to {@code this}
		 * @param gen the code generator
		 */
		public BlockTransition(Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen) {
			this(localThis, gen, new LinkedHashSet<>(), new LinkedHashSet<>());
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
		 * @param <N> the tail of the stack (...)
		 * @param em the emitter
		 * @return the emitter with ...
		 */
		public <N extends Next> Emitter<N> genFwd(Emitter<N> em) {
			return em
					.emit(VarGen::genRetire, localThis, gen, toRetire)
					.emit(VarGen::genBirth, localThis, gen, toBirth);
		}

		/**
		 * Emit bytecode for the reverse transition
		 * 
		 * <p>
		 * Sometimes "transitions" are used around hazards, notably {@link CallOtherOpGen}. This
		 * method is used after the hazard to restore the live variables in scope.
		 * ({@link #genFwd(Emitter)} is used before the hazard.) Variables that were retired and
		 * re-birthed here. There should not have been any variables birthed going into the hazard.
		 * 
		 * @param <N> the tail of the stack (...)
		 * @param em the emitter
		 * @return the emitter with ...
		 */
		public <N extends Next> Emitter<N> genInv(Emitter<N> em) {
			return em
					.emit(VarGen::genRetire, localThis, gen, toBirth)
					.emit(VarGen::genBirth, localThis, gen, toRetire);
		}
	}

	/**
	 * Compute the retired and birthed varnodes for a transition between the given blocks.
	 * 
	 * <p>
	 * Either block may be {@code null} to indicate entering or leaving the passage. Additionally,
	 * the {@code to} block should be {@code null} when generating transitions around a hazard.
	 * 
	 * @param <THIS> the type of the generated class
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param from the block control flow is leaving (whether by branch or fall through)
	 * @param to the block control flow is entering
	 * @return the means of generating bytecode at the transition
	 */
	static <THIS extends JitCompiledPassage> BlockTransition<THIS> computeBlockTransition(
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitBlock from, JitBlock to) {
		JitVarScopeModel scopeModel = gen.getVariableScopeModel();
		Set<Varnode> liveFrom = from == null ? Set.of() : scopeModel.getLiveVars(from);
		Set<Varnode> liveTo = to == null ? Set.of() : scopeModel.getLiveVars(to);
		BlockTransition<THIS> result = new BlockTransition<>(localThis, gen);

		result.toRetire.addAll(liveFrom);
		result.toRetire.removeAll(liveTo);

		result.toBirth.addAll(liveTo);
		result.toBirth.removeAll(liveFrom);

		return result;
	}

	/**
	 * Write a value from a stack operand into the given variable
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <T> the JVM type of the stack operand
	 * @param <JT> the p-code type of the stack operand
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param v the variable to write
	 * @param type the p-code type of the stack operand
	 * @param ext the kind of extension to apply when adjusting from varnode size to JVM size
	 * @param scope a scope for temporaries
	 * @return the emitter with ...
	 */
	<THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N1 extends Next, N0 extends Ent<N1, T>> Emitter<N1> genWriteFromStack(Emitter<N0> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v, JT type, Ext ext,
				Scope scope);

	/**
	 * Write a value from a local operand into the given variable
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param v the variable to write
	 * @param opnd the source operand
	 * @param ext the kind of extension to apply when adjusting from varnode size to JVM size
	 * @param scope a scope for temporaries
	 * @return the emitter with ...
	 */
	<THIS extends JitCompiledPassage, N extends Next> Emitter<N> genWriteFromOpnd(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v, Opnd<MpIntJitType> opnd,
			Ext ext, Scope scope);

	/**
	 * Write a value from an array operand into the given variable
	 * 
	 * @param <THIS> the type of the generated class
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., arrayref
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param gen the code generator
	 * @param v the variable to write
	 * @param type the p-code type of the array operand
	 * @param ext the kind of extension to apply when adjusting from varnode size to JVM size
	 * @param scope a scope for temporaries
	 * @return the emitter with ...
	 */
	<THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<N1>
			genWriteFromArray(Emitter<N0> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, V v, MpIntJitType type, Ext ext, Scope scope);
}
