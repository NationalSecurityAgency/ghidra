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

import java.lang.reflect.*;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.JitPassage.DecodedPcodeOp;
import ghidra.pcode.emu.jit.analysis.*;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator.PcGen;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator.RetireMode;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.gen.var.VarGen.BlockTransition;
import ghidra.pcode.emu.jit.op.JitCallOtherDefOp;
import ghidra.pcode.emu.jit.op.JitCallOtherOpIf;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary.OpOutput;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The generator for a {@link JitCallOtherOpIf callother}.
 * 
 * <p>
 * The checks if Direct invocation is possible. If so, it emits code using
 * {@link #genRunDirectStrategy(Emitter, Local, JitCodeGenerator, JitCallOtherOpIf, JitBlock, Scope)}.
 * If not, it emits code using
 * {@link #genRunRetirementStrategy(Emitter, Local, JitCodeGenerator, PcodeOp, JitBlock, PcodeUseropDefinition)}.
 * Direct invocation is possible when the userop is {@link PcodeUseropDefinition#isFunctional()
 * functional} and all of its parameters and return type have a supported primitive type.
 * ({@code char} is not supported.) Regarding the invocation strategies, see
 * {@link JitDataFlowUseropLibrary} and note that the Inline strategy is already handled by this
 * point.
 * 
 * <p>
 * For the Standard strategy, we emit code to retire the program counter, decode context, and all
 * live variables. We then request a field to hold the {@link PcodeOp#CALLOTHER} p-code op and the
 * userop, and emit code to load them. We then emit code to invoke
 * {@link JitCompiledPassage#invokeUserop(PcodeUseropDefinition, PcodeOp)}. The userop definition
 * handles retrieving all of its inputs and writing the output, directly to the
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
 * result is returned, but no output operand is provided, we <em>must</em> still emit a
 * {@link Op#pop(Emitter) pop}.
 */
public enum CallOtherOpGen implements OpGen<JitCallOtherOpIf> {
	/** The generator singleton */
	GEN;

	/**
	 * Emit code to implement the Standard strategy (see the class documentation)
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param em the emitter typed with the empty stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param op the p-code op
	 * @param block the block containing the op
	 * @param userop the userop definition, wrapped by the {@link JitDataFlowUseropLibrary}
	 * @return the result of emitting the userop's bytecode
	 */
	public static <THIS extends JitCompiledPassage> OpResult genRunRetirementStrategy(
			Emitter<Bot> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
			PcodeOp op, JitBlock block, PcodeUseropDefinition<?> userop) {
		/**
		 * This is about the simplest (laziest) approach we could take, but it should suffice when
		 * we cannot invoke directly. We immediately retire all variables, then invoke the userop as
		 * it would be by the p-code interpreter. It can access its variables in the usual fashion.
		 * Although not ideal, it can also feed the executor (interpreter) ops to execute --- they
		 * won't be jitted here. Then, we liven the variables back.
		 * <p>
		 * NOTE: The output variable should be "alive", so we need not store it into a local. It'll
		 * be made alive in the return block transition.
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		FieldForUserop useropField = gen.requestFieldForUserop((PcodeUseropDefinition) userop);
		FieldForPcodeOp opField = gen.requestStaticFieldForOp(op);

		BlockTransition<THIS> transition =
			VarGen.computeBlockTransition(localThis, gen, block, null);

		PcGen pcGen = PcGen.loadOffset(gen.getAddressForOp(op));

		return new LiveOpResult(em
				.emit(transition::genFwd)
				.emit(gen::genRetirePcCtx, localThis, pcGen, gen.getExitContext(op), RetireMode.SET)
				.emit(Op::aload, localThis)
				.emit(useropField::genLoad, localThis, gen)
				.emit(opField::genLoad, gen)
				.emit(Op::invokeinterface, T_JIT_COMPILED_PASSAGE, "invokeUserop",
					MDESC_JIT_COMPILED_PASSAGE__INVOKE_USEROP)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid)
				.emit(transition::genInv));
	}

	static Parameter findOutputParameter(Parameter[] parameters, Method method) {
		List<Parameter> found =
			Stream.of(parameters).filter(p -> p.getAnnotation(OpOutput.class) != null).toList();
		return switch (found.size()) {
			case 0 -> null;
			case 1 -> {
				Parameter p = found.get(0);
				if (p.getType() == int[].class) {
					yield p;
				}
				throw new IllegalArgumentException("""
						@%s requires parameter to have type int[] when functional=true. \
						Got %s (method %s)""".formatted(
					OpOutput.class.getSimpleName(), p, method.getName()));
			}
			default -> {
				throw new IllegalArgumentException("""
						@%s can only be applied to one parameter of method %s. \
						It is applied to: %s""".formatted(
					OpOutput.class.getSimpleName(), method.getName(),
					found.stream().map(Parameter::toString).collect(Collectors.joining(", "))));
			}
		};
	}

	static <E> List<E> tail(List<E> list) {
		return list.subList(1, list.size());
	}

	record PlacedParam<N>(Emitter<N> em, List<JitVal> args, List<Parameter> params) {}

	/**
	 * Emit code to implement the Direct strategy (see the class documentation)
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param em the emitter typed with the empty stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param op the p-code op use-def node
	 * @param block the block containing the op
	 * @param scope a scope for generating temporary local storage
	 * @return the result of emitting the userop's bytecode
	 */
	public static <THIS extends JitCompiledPassage, LIB extends PcodeUseropLibrary<?>> OpResult
			genRunDirectStrategy(Emitter<Bot> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, JitCallOtherOpIf op, JitBlock block, Scope scope) {
		@SuppressWarnings({ "rawtypes", "unchecked" })
		FieldForUserop useropField = gen.requestFieldForUserop((PcodeUseropDefinition) op.userop());

		// Set<Varnode> live = gen.vsm.getLiveVars(block);
		/**
		 * NOTE: It doesn't matter if there are live variables. We still have to "retire" the
		 * program counter and contextreg if the userop throws an exception.
		 */

		Method method = op.userop().getJavaMethod();

		Parameter[] parameters = method.getParameters();
		Parameter outputParameter = findOutputParameter(parameters, method);
		if (outputParameter != null && method.getReturnType() != void.class) {
			throw new IllegalArgumentException("""
					@%s cannot be applied to any parameter of a method returning non-void. \
					It's applied to %s of %s""".formatted(
				OpOutput.class.getSimpleName(), outputParameter, method.getName()));
		}

		Local<TRef<int[]>> localOut;
		MpIntJitType outMpType;

		if (outputParameter != null) {
			localOut = scope.decl(Types.T_INT_ARR, "out");
			if (op instanceof JitCallOtherDefOp defOp) {
				outMpType = MpIntJitType.forSize(defOp.out().size());
				em = em
						.emit(Op::ldc__i, outMpType.legsAlloc())
						.emit(Op::newarray, Types.T_INT)
						.emit(Op::astore, localOut);
			}
			else {
				outMpType = null;
				em = em
						.emit(Op::aconst_null, Types.T_INT_ARR)
						.emit(Op::astore, localOut);
			}
		}
		else {
			outMpType = null;
			localOut = null;
		}

		TRef<LIB> libType = Types.refExtends(T_PCODE_USEROP_LIBRARY, method.getDeclaringClass());

		var rec = new Object() {
			<N extends Next> Emitter<? extends Ent<N, ?>> doReadArg(Emitter<N> em, JitVal arg,
					Parameter param) {
				if (param.getType() == boolean.class) {
					return gen.genReadToBool(em, localThis, arg);
				}
				if (param.getType() == int[].class) {
					MpIntJitType t = MpIntJitType.forSize(arg.size());
					// TODO: Annotation/attribute to specify slack?
					return gen.genReadToArray(em, localThis, arg, t, Ext.ZERO, scope, 0);
				}
				return switch (JitType.forJavaType(param.getType())) {
					case IntJitType t -> gen.genReadToStack(em, localThis, arg, t, Ext.ZERO);
					case LongJitType t -> gen.genReadToStack(em, localThis, arg, t, Ext.ZERO);
					case FloatJitType t -> gen.genReadToStack(em, localThis, arg, t, Ext.ZERO);
					case DoubleJitType t -> gen.genReadToStack(em, localThis, arg, t, Ext.ZERO);
					default -> throw new AssertionError();
				};
			}

			<N extends Next> PlacedParam<? extends Ent<N, ?>> placeNextParam(Emitter<N> em,
					List<JitVal> args, List<Parameter> params) {
				Parameter param = params.getFirst();
				if (param == outputParameter) {
					var emNext = em.emit(Op::aload, localOut);
					return new PlacedParam<>(emNext, args, tail(params));
				}
				JitVal arg = args.getFirst();
				var emNext = doReadArg(em, arg, param);
				return new PlacedParam<>(emNext, tail(args), tail(params));
			}

			<N extends Next> Inv<?, N, Bot> doInvVirtual(Emitter<N> em, List<JitVal> args,
					List<Parameter> params) {
				var emLib = em
						.emit(useropField::genLoad, localThis, gen)
						.emit(Op::invokeinterface, T_PCODE_USEROP_DEFINITION, "getDefiningLibrary",
							MDESC_PCODE_USEROP_DEFINITION__GET_DEFINING_LIBRARY)
						.step(Inv::takeObjRef)
						.step(Inv::ret)
						.emit(Op::checkcast, libType);
				var inv = doInvVirtualRec(emLib, args, params)
						.step(Inv::takeQObjRef);
				return inv;
			}

			<N extends Next> ObjInv<?, LIB, N, ?> doInvVirtualRec(Emitter<N> em, List<JitVal> args,
					List<Parameter> params) {
				if (params.isEmpty()) {
					/**
					 * NOTE: Can't put try-catch block here because the handler's all expect
					 * Ent<Bot,Throwable>
					 */
					return Op.invokevirtual(em, libType, method.getName(), MthDesc.reflect(method),
						false);
				}
				PlacedParam<? extends Ent<N, ?>> next = placeNextParam(em, args, params);
				ObjInv<?, LIB, ? extends Ent<N, ?>, ?> inv =
					doInvVirtualRec(next.em, next.args, next.params);
				return Inv.takeQArg(inv);
			}

			<N extends Next> Inv<?, N, ?> doInvStaticRec(Emitter<N> em, List<JitVal> args,
					List<Parameter> params) {
				if (params.isEmpty()) {
					return Op.invokestatic(em, libType, method.getName(), MthDesc.reflect(method),
						false);
				}
				PlacedParam<? extends Ent<N, ?>> next = placeNextParam(em, args, params);
				Inv<?, ? extends Ent<N, ?>, ?> inv =
					doInvStaticRec(next.em, next.args, next.params);
				return Inv.takeQArg(inv);
			}

			<N extends Next> Inv<?, N, ?> doInvStatic(Emitter<N> em, List<JitVal> args,
					List<Parameter> params) {
				return doInvStaticRec(em, args, params);
			}
		};

		var tryCatchBlock = Misc.tryCatch(em, Lbl.create(),
			gen.requestExceptionHandler((DecodedPcodeOp) op.op(), block).lbl(),
			GenConsts.T_THROWABLE);
		em = tryCatchBlock.em();

		var inv = Modifier.isStatic(method.getModifiers())
				? rec.doInvStatic(em, op.args(), Arrays.asList(parameters))
				: rec.doInvVirtual(em, op.args(), Arrays.asList(parameters));

		if (outputParameter != null) {
			if (outMpType != null && op instanceof JitCallOtherDefOp defOp) {
				em = inv
						.step(Inv::retQVoid)
						.emit(Op::aload, localOut)
						.emit(gen::genWriteFromArray, localThis, defOp.out(), outMpType, Ext.ZERO,
							scope);
			}
			// Else there's either no @OpOutput or the output operand is absent
		}
		else if (op instanceof JitCallOtherDefOp defOp) {
			// TODO: Can annotation specify signedness of return value?
			var write = new Object() {
				public <T extends BPrim<?>, JT extends SimpleJitType<T, JT>> Emitter<Bot> doWrite(
						Inv<?, Bot, ?> inv, Class<?> returnType) {
					JT type = SimpleJitType.forJavaType(returnType);
					return inv
							.step(Inv::retQ, type.bType())
							.emit(gen::genWriteFromStack, localThis, defOp.out(), type, Ext.ZERO,
								scope);
				}
			};
			em = inv.step(write::doWrite, method.getReturnType());
		}
		else if (method.getReturnType() != void.class) {
			em = switch (JitType.forJavaType(method.getReturnType())) {
				case IntJitType t -> inv
						.step(Inv::retQ, t.bType())
						.emit(Op::pop);
				case LongJitType t -> inv
						.step(Inv::retQ, t.bType())
						.emit(Op::pop2__2);
				case FloatJitType t -> inv
						.step(Inv::retQ, t.bType())
						.emit(Op::pop);
				case DoubleJitType t -> inv
						.step(Inv::retQ, t.bType())
						.emit(Op::pop2__2);
				default -> throw new AssertionError();
			};
		}
		return new LiveOpResult(em
				.emit(Lbl::place, tryCatchBlock.end()));
	}

	/**
	 * Check if the Direct invocation strategy is applicable (see class documentation)
	 * 
	 * @param op the p-code op use-def node
	 * @return true if applicable
	 */
	public static boolean canDoDirectInvocation(JitCallOtherOpIf op) {
		if (!op.userop().isFunctional() || op.userop().modifiesContext()) {
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
	public <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitCallOtherOpIf op, JitBlock block, Scope scope) {
		if (op.userop().modifiesContext()) {
			em = em
					.emit(Op::ldc__i, 1)
					.emit(Op::istore, localCtxmod);
		}
		if (canDoDirectInvocation(op)) {
			return genRunDirectStrategy(em, localThis, gen, op, block, scope);
		}
		return genRunRetirementStrategy(em, localThis, gen, op.op(), block, op.userop());
	}
}
