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
package ghidra.pcode.emu.jit.gen.opnd;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.GenConsts;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd.SimpleOpndEm;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * A (sometimes temporary) operand
 * <p>
 * This class is also the namespace for a number of convesion operations. Please note that
 * "conversions" here deal entirely in bits. While a lot of machinery is needed to represent p-code
 * values, esp., when the number of bytes exceeds a JVM long, in essence, every conversion
 * operation, if it performs any operation at all, is merely <em>bit</em> truncation or extension.
 * Otherwise, all we are doing is convincing the JVM that the operand's type has changed. In
 * particular, an int-to-float conversion is <em>not</em> accomplished using {@link Op#i2f(Emitter)
 * i2f}, as that would actually change the raw bit contents of the value. Rather, we use
 * {@link Float#intBitsToFloat(int)}.
 * 
 * @param <T> the p-code type
 */
public interface Opnd<T extends JitType> {

	/**
	 * An operand-emitter tuple
	 * 
	 * @param <T> the p-code type of the operand
	 * @param <N> the stack of the emitter
	 */
	record OpndEm<T extends JitType, N extends Next>(Opnd<T> opnd, Emitter<N> em) {

		@SuppressWarnings({ "unchecked", "rawtypes" })
		public <TT extends JitType> OpndEm<TT, N> castBack(TT to, T from) {
			assert from == to;
			return (OpndEm) this;
		}
	}

	/**
	 * An interface for converting between simple stack operands
	 * 
	 * @param <FT> the "from" JVM type
	 * @param <FJT> the "from" p-code type
	 * @param <TT> the "to" JVM type
	 * @param <TJT> the "to" p-code type
	 */
	interface StackToStackConv<
		FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>,
		TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>> {

		/**
		 * Convert a stack operand to another stack operand
		 * 
		 * @param <N1> the tail of the stack (...)
		 * @param <N0> ..., value
		 * @param em the emitter
		 * @param from the source p-code type
		 * @param to the destination p-code type
		 * @param ext the kind of extension to apply
		 * @return the emitter with ..., result
		 */
		<N1 extends Next, N0 extends Ent<N1, FT>> Emitter<Ent<N1, TT>>
				convertStackToStack(Emitter<N0> em, FJT from, TJT to, Ext ext);
	}

	/**
	 * An interface for converting simple stack operands to multi-precision operands
	 * 
	 * @param <FT> the "from" JVM type
	 * @param <FJT> the "from" p-code type
	 * @param <TT> the "to" JVM type for each mp leg
	 * @param <TLT> the "to" p-code type for each mp leg
	 * @param <TJT> the "to" p-code type
	 */
	interface StackToMpConv<
		FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>,
		TT extends BPrim<?>, TLT extends SimpleJitType<TT, TLT>,
		TJT extends LeggedJitType<TT, TLT>> {

		/**
		 * Convert a stack operand to an mp operand in locals
		 * 
		 * @param <N1> the tail of the stack (...)
		 * @param <N0> ..., value
		 * @param em the emitter
		 * @param from the source p-code type
		 * @param name the name to give the resulting operand
		 * @param to the destination p-code type
		 * @param ext the kind of extension to apply
		 * @param scope a scope for generated temporary locals
		 * @return the resulting operand and the emitter with ...
		 */
		<N1 extends Next, N0 extends Ent<N1, FT>> OpndEm<TJT, N1> convertStackToOpnd(Emitter<N0> em,
				FJT from, String name, TJT to, Ext ext, Scope scope);

		/**
		 * Convert a stack operand to an mp operand in an array
		 * 
		 * @param <N1> the tail of the stack (...)
		 * @param <N0> ..., value
		 * @param em the emitter
		 * @param from the source p-code type
		 * @param name the name to give the resulting operand
		 * @param to the destination p-code type
		 * @param ext the kind of extension to apply
		 * @param scope a scope for generated temporary locals
		 * @param slack the number of extra (more significant) elements to allocate in the array
		 * @return the emitter with ..., arrayref
		 */
		<N1 extends Next, N0 extends Ent<N1, FT>> Emitter<Ent<N1, TRef<int[]>>> convertStackToArray(
				Emitter<N0> em, FJT from, String name, TJT to, Ext ext, Scope scope, int slack);
	}

	/**
	 * An interface for converting multi-precision operands to simple stack operands
	 * 
	 * @param <FT> the "from" JVM type for each mp leg
	 * @param <FLT> the "from" p-code type for each mp leg
	 * @param <FJT> the "from" p-code type
	 * @param <TT> the "to" JVM type
	 * @param <TJT> the "to" p-code type
	 */
	interface MpToStackConv<
		FT extends BPrim<?>, FLT extends SimpleJitType<FT, FLT>,
		FJT extends LeggedJitType<FT, FLT>,
		TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>> {

		/**
		 * Convert an mp operand in locals to a stack operand
		 * 
		 * @param <N> the tail of the stack (...)
		 * @param em the emitter
		 * @param from the source operand
		 * @param to the destination p-code type
		 * @param ext the kind of extension to apply
		 * @return the emitter with ..., result
		 */
		<N extends Next> Emitter<Ent<N, TT>> convertOpndToStack(Emitter<N> em, Opnd<FJT> from,
				TJT to, Ext ext);

		/**
		 * Convert an mp operand in an array to a stack operand
		 * 
		 * @param <N1> the tail of the stack (...)
		 * @param <N0> ..., arrayref
		 * @param em the emitter
		 * @param from the source p-code type
		 * @param to the destination p-code type
		 * @param ext the kind of extension to apply
		 * @return the emitter with ..., result
		 */
		<N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<Ent<N1, TT>>
				convertArrayToStack(Emitter<N0> em, FJT from, TJT to, Ext ext);
	}

	/**
	 * An interface for converting between multi-precision operands
	 * 
	 * @param <FT> the "from" JVM type for each mp leg
	 * @param <FLT> the "from" p-code type for each mp leg
	 * @param <FJT> the "from" p-code type
	 * @param <TT> the "to" JVM type for each mp leg
	 * @param <TLT> the "to" p-code type for each mp leg
	 * @param <TJT> the "to" p-code type
	 */
	interface MpToMpConv<
		FT extends BPrim<?>, FLT extends SimpleJitType<FT, FLT>,
		FJT extends LeggedJitType<FT, FLT>,
		TT extends BPrim<?>, TLT extends SimpleJitType<TT, TLT>,
		TJT extends LeggedJitType<TT, TLT>> {

		/**
		 * Convert an operand in locals to another in locals
		 * <p>
		 * NOTE: This may be accomplished in part be re-using legs from the source operand in the
		 * destination operand
		 * 
		 * @param <N> the tail of the stack (...)
		 * @param em the emitter
		 * @param from the source operand
		 * @param to the destination p-code type
		 * @param ext the kind of extension to apply
		 * @param scope a scope for generated temporary variables
		 * @return the resulting operand and emitter with ...
		 */
		<N extends Next> OpndEm<TJT, N> convertOpndToOpnd(Emitter<N> em, Opnd<FJT> from, TJT to,
				Ext ext, Scope scope);

		/**
		 * Convert an operand in locals to an array
		 * 
		 * @param <N> the tail of the stack (...)
		 * @param em the emitter
		 * @param from the source operand
		 * @param to the destination p-code type
		 * @param ext the kind of extension to apply
		 * @param scope a scope for generated temporary variables
		 * @param slack the number of extra (more significant) elements to allocate in the array
		 * @return the emitter with ..., arrayref
		 */
		<N extends Next> Emitter<Ent<N, TRef<int[]>>> convertOpndToArray(Emitter<N> em,
				Opnd<FJT> from, TJT to, Ext ext, Scope scope, int slack);
	}

	/**
	 * Check if the given int-to-int conversion would require extension
	 * 
	 * @param from the source p-code type
	 * @param to the destination p-code type
	 * @return true if extension is needed, i.e., {@code to} is strictly larger than {@code from}
	 */
	static boolean needsIntExt(IntJitType from, IntJitType to) {
		return to.size() < from.size();
	}

	/**
	 * Check if the given long-to-long conversion would require extension
	 * 
	 * @param from the source p-code type
	 * @param to the destination p-code type
	 * @return true if extension is needed, i.e., {@code to} is strictly larger than {@code from}
	 */
	static boolean needsLongExt(LongJitType from, LongJitType to) {
		return to.size() < from.size();
	}

	/**
	 * Emit a long left shift, selecting signed or unsigned by the given extension
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @param ext the kind of extension to apply
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TLong>> lextshr(Emitter<N0> em, Ext ext) {
		return switch (ext) {
			case ZERO -> em.emit(Op::lushr);
			case SIGN -> em.emit(Op::lshr);
		};
	}

	/**
	 * Converter from int to int
	 */
	enum IntToInt implements StackToStackConv<TInt, IntJitType, TInt, IntJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>>
				convertStackToStack(Emitter<N0> em, IntJitType from, IntJitType to, Ext ext) {
			if (!needsIntExt(from, to)) {
				return em.emit(Misc::cast1);
			}
			int shamt = Integer.SIZE - to.size() * Byte.SIZE;
			return switch (ext) {
				case ZERO -> em
						.emit(Op::ldc__i, -1 >>> shamt)
						.emit(Op::iand);
				case SIGN -> switch (to.size()) {
					case 1 -> em
							.emit(Op::i2b);
					case 2 -> em
							.emit(Op::i2s);
					default -> em // 3 is all that's really left
							.emit(Op::ldc__i, shamt)
							.emit(Op::ishl)
							.emit(Op::ldc__i, shamt)
							.emit(Op::ishr);
				};
			};
		}
	}

	/**
	 * Converter from int to long
	 */
	enum IntToLong implements StackToStackConv<TInt, IntJitType, TLong, LongJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TLong>>
				convertStackToStack(Emitter<N0> em, IntJitType from, LongJitType to, Ext ext) {
			return switch (ext) {
				case ZERO -> em
						.emit(Op::invokestatic, GenConsts.TR_INTEGER, "toUnsignedLong",
							GenConsts.MDESC_INTEGER__TO_UNSIGNED_LONG, false)
						.step(Inv::takeArg)
						.step(Inv::ret);
				case SIGN -> em
						.emit(IntToInt.INSTANCE::convertStackToStack, from, IntJitType.I4, ext)
						.emit(Op::i2l);
			};
		}
	}

	/**
	 * Converter from int to mp-int
	 */
	enum IntToMpInt implements StackToMpConv<TInt, IntJitType, TInt, IntJitType, MpIntJitType> {
		INSTANCE;

		public <N extends Next> OpndEm<MpIntJitType, N> doConvert(Emitter<N> em,
				SimpleOpnd<TInt, IntJitType> temp, String name, MpIntJitType to, Ext ext,
				Scope scope) {
			List<SimpleOpnd<TInt, IntJitType>> legs = new ArrayList<>();
			IntJitType typeLsl = to.legTypesLE().get(0);
			var lsl = Opnd.needsIntExt(temp.type(), typeLsl)
					? em
							.emit(temp::read)
							.emit(IntToInt.INSTANCE::convertStackToStack, temp.type(), typeLsl, ext)
							.emit(temp::write, scope)
					: new SimpleOpndEm<>(temp, em);
			legs.add(lsl.opnd());
			var sign = switch (ext) {
				case ZERO -> new SimpleOpndEm<>(IntConstOpnd.ZERO_I4, em);
				case SIGN -> lsl.em()
						.emit(lsl.opnd()::read)
						.emit(Op::ldc__i, Integer.SIZE - 1)
						.emit(Op::ishr)
						.emit(Opnd::createIntReadOnly, IntJitType.I4, "%s_convSign".formatted(name),
							scope);
			};
			for (int i = 1; i < to.legsAlloc(); i++) {
				legs.add(sign.opnd());
			}
			return new OpndEm<>(MpIntLocalOpnd.of(to, "%s_convMpInt".formatted(name), legs),
				sign.em());
		}

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TInt>> OpndEm<MpIntJitType, N1>
				convertStackToOpnd(Emitter<N0> em, IntJitType from, String name, MpIntJitType to,
						Ext ext, Scope scope) {
			IntJitType typeLsl = to.legTypesLE().get(0);
			var lsl = em
					.emit(IntToInt.INSTANCE::convertStackToStack, from, typeLsl, ext)
					.emit(IntLocalOpnd.temp(typeLsl, "%s_convLeg0".formatted(name), scope)::write,
						scope);
			return doConvert(lsl.em(), lsl.opnd(), name, to, ext, scope);
		}

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TRef<int[]>>>
				convertStackToArray(Emitter<N0> em, IntJitType from, String name, MpIntJitType to,
						Ext ext, Scope scope, int slack) {
			int legCount = to.legsAlloc();
			Local<TRef<int[]>> arr = scope.decl(Types.T_INT_ARR, "%s_convArr".formatted(name));
			try (SubScope ss = scope.sub()) {
				IntJitType typeLsl = to.legTypesLE().get(0);
				Local<TInt> lsl = ss.decl(typeLsl.bType(), "temp_lsl");
				var ckExt = em
						.emit(IntToInt.INSTANCE::convertStackToStack, from, typeLsl, ext)
						.emit(Op::istore, lsl)
						.emit(Op::ldc__i, legCount + slack)
						.emit(Op::newarray, Types.T_INT)
						.emit(Op::astore, arr)
						.emit(Op::aload, arr)
						.emit(Op::ldc__i, 0)
						.emit(Op::iload, lsl)
						.emit(Op::iastore);
				switch (ext) {
					case ZERO -> {
					}
					case SIGN -> {
						Local<TInt> sign = ss.decl(Types.T_INT, "temp_sign");
						ckExt = ckExt
								.emit(Op::iload, lsl)
								.emit(Op::ldc__i, Integer.SIZE - 1)
								.emit(Op::ishr)
								.emit(Op::istore, sign);
						for (int i = 1; i < legCount; i++) {
							ckExt = ckExt
									.emit(Op::aload, arr)
									.emit(Op::ldc__i, i)
									.emit(Op::iload, sign)
									.emit(Op::iastore);
						}
					}
				}
				return ckExt
						.emit(Op::aload, arr);
			}
		}
	}

	/**
	 * Converter from int to float
	 */
	enum IntToFloat implements StackToStackConv<TInt, IntJitType, TFloat, FloatJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TFloat>>
				convertStackToStack(Emitter<N0> em, IntJitType from, FloatJitType to, Ext ext) {
			return em
					.emit(Op::invokestatic, GenConsts.TR_FLOAT, "intBitsToFloat",
						GenConsts.MDESC_FLOAT__INT_BITS_TO_FLOAT, false)
					.step(Inv::takeArg)
					.step(Inv::ret);
		}
	}

	/**
	 * Converter from int to double
	 */
	enum IntToDouble implements StackToStackConv<TInt, IntJitType, TDouble, DoubleJitType> {
		INSTANCE; // In theory, should never happen, but if it does, truncate.

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TDouble>>
				convertStackToStack(Emitter<N0> em, IntJitType from, DoubleJitType to, Ext ext) {
			return em
					.emit(IntToLong.INSTANCE::convertStackToStack, from, LongJitType.I8, ext)
					.emit(LongToDouble.INSTANCE::convertStackToStack, LongJitType.I8, to, ext);
		}
	}

	/**
	 * Converter from long to int
	 */
	enum LongToInt implements StackToStackConv<TLong, LongJitType, TInt, IntJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TInt>>
				convertStackToStack(Emitter<N0> em, LongJitType from, IntJitType to, Ext ext) {
			return em
					.emit(Op::l2i)
					.emit(IntToInt.INSTANCE::convertStackToStack, IntJitType.I4, to, ext);
		}
	}

	/**
	 * Converter from long to long
	 */
	enum LongToLong implements StackToStackConv<TLong, LongJitType, TLong, LongJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TLong>>
				convertStackToStack(Emitter<N0> em, LongJitType from, LongJitType to, Ext ext) {
			if (!needsLongExt(from, to)) {
				return em.emit(Misc::cast1);
			}
			int shamt = Long.SIZE - to.size() * Byte.SIZE;
			return switch (ext) {
				case ZERO -> em
						.emit(Op::ldc__l, -1L >>> shamt)
						.emit(Op::land);
				case SIGN -> em
						.emit(Op::ldc__i, shamt)
						.emit(Op::lshl)
						.emit(Op::ldc__i, shamt)
						.emit(Op::lshr);
			};
		}
	}

	/**
	 * Converter from long to mp-int
	 */
	enum LongToMpInt implements StackToMpConv<TLong, LongJitType, TInt, IntJitType, MpIntJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TLong>> OpndEm<MpIntJitType, N1>
				convertStackToOpnd(Emitter<N0> em, LongJitType from, String name, MpIntJitType to,
						Ext ext, Scope scope) {
			var upperOnStack = em
					.emit(Op::dup2__2)
					.emit(Op::ldc__i, Integer.SIZE)
					.emit(Opnd::lextshr, ext)
					.emit(Op::l2i);
			var sign = switch (ext) {
				case ZERO -> new SimpleOpndEm<>(IntConstOpnd.ZERO_I4, upperOnStack);
				case SIGN -> upperOnStack
						.emit(Op::dup)
						.emit(Op::ldc__i, Integer.SIZE - 1)
						.emit(Op::ishr)
						.emit(Opnd::createIntReadOnly, IntJitType.I4, "%s_convSign".formatted(name),
							scope);
			};
			upperOnStack = sign.em();

			List<SimpleOpnd<TInt, IntJitType>> legs = new ArrayList<>();
			SimpleOpnd<TInt, IntJitType> lower =
				IntLocalOpnd.temp(IntJitType.I4, "%s_convLegLower".formatted(name), scope);
			legs.add(lower); // We'll initialize it last

			var upper = sign.em()
					.emit(IntLocalOpnd::create, IntJitType.I4, "%s_convLegUpper".formatted(name),
						scope);
			legs.add(upper.opnd());

			for (int i = 2; i < to.legsAlloc(); i++) {
				legs.add(sign.opnd());
			}

			return new OpndEm<>(MpIntLocalOpnd.of(to, "%s_convMpInt".formatted(name), legs),
				upper.em()
						.emit(Op::l2i)
						.emit(lower::writeDirect));
		}

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TRef<int[]>>>
				convertStackToArray(Emitter<N0> em, LongJitType from, String name, MpIntJitType to,
						Ext ext, Scope scope, int slack) {
			int legCount = to.legsAlloc();
			Local<TRef<int[]>> arr = scope.decl(Types.T_INT_ARR, "%s_convArr".formatted(name));
			try (SubScope ss = scope.sub()) {
				IntJitType typeLsl = to.legTypesLE().get(0);
				IntJitType typeMsl = to.legTypesLE().get(1);
				Local<TInt> lsl = ss.decl(typeLsl.bType(), "temp_lsl");
				Local<TInt> msl = ss.decl(typeMsl.bType(), "temp_msl");
				var ckExt = em
						.emit(Op::dup2__2)
						.emit(Op::l2i)
						.emit(Op::istore, lsl)

						.emit(Op::ldc__i, Integer.SIZE)
						.emit(Opnd::lextshr, ext)
						.emit(Op::l2i)
						.emit(Op::istore, msl)

						.emit(Op::ldc__i, legCount + slack)
						.emit(Op::newarray, Types.T_INT)
						.emit(Op::astore, arr)

						.emit(Op::aload, arr)
						.emit(Op::ldc__i, 0)
						.emit(Op::iload, lsl)
						.emit(Op::iastore)

						.emit(Op::aload, arr)
						.emit(Op::ldc__i, 1)
						.emit(Op::iload, msl)
						.emit(Op::iastore);
				switch (ext) {
					case ZERO -> {
					}
					case SIGN -> {
						Local<TInt> sign = ss.decl(Types.T_INT, "temp_sign");
						ckExt = ckExt
								.emit(Op::iload, msl)
								.emit(Op::ldc__i, Integer.SIZE - 1)
								.emit(Op::ishr)
								.emit(Op::istore, sign);
						for (int i = 2; i < legCount; i++) {
							ckExt = ckExt
									.emit(Op::aload, arr)
									.emit(Op::ldc__i, i)
									.emit(Op::iload, sign)
									.emit(Op::iastore);
						}
					}
				}
				return ckExt
						.emit(Op::aload, arr);
			}
		}
	}

	/**
	 * Converter from long to float
	 */
	enum LongToFloat implements StackToStackConv<TLong, LongJitType, TFloat, FloatJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TFloat>>
				convertStackToStack(Emitter<N0> em, LongJitType from, FloatJitType to, Ext ext) {
			return em
					.emit(LongToInt.INSTANCE::convertStackToStack, from, IntJitType.I4, ext)
					.emit(IntToFloat.INSTANCE::convertStackToStack, IntJitType.I4, to, ext);
		}
	}

	/**
	 * Converter from long to double
	 */
	enum LongToDouble implements StackToStackConv<TLong, LongJitType, TDouble, DoubleJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TDouble>>
				convertStackToStack(Emitter<N0> em, LongJitType from, DoubleJitType to, Ext ext) {
			if (to.size() != from.size()) {
				throw new AssertionError("Size mismatch");
			}
			return em
					.emit(Op::invokestatic, GenConsts.TR_DOUBLE, "longBitsToDouble",
						GenConsts.MDESC_DOUBLE__LONG_BITS_TO_DOUBLE, false)
					.step(Inv::takeArg)
					.step(Inv::ret);
		}
	}

	/**
	 * Converter from mp-int to (simple) int
	 */
	enum MpIntToInt implements MpToStackConv<TInt, IntJitType, MpIntJitType, TInt, IntJitType> {
		INSTANCE;

		@Override
		public <N extends Next> Emitter<Ent<N, TInt>> convertOpndToStack(Emitter<N> em,
				Opnd<MpIntJitType> from, IntJitType to, Ext ext) {
			var lsl = from.type().castLegsLE(from).get(0);
			return em
					.emit(lsl::read)
					.emit(IntToInt.INSTANCE::convertStackToStack, lsl.type(), to, ext);
		}

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<Ent<N1, TInt>>
				convertArrayToStack(Emitter<N0> em, MpIntJitType from, IntJitType to, Ext ext) {
			var typeLsl = from.legTypesLE().get(0);
			return em
					.emit(Op::ldc__i, 0)
					.emit(Op::iaload)
					.emit(IntToInt.INSTANCE::convertStackToStack, typeLsl, to, ext);
		}
	}

	/**
	 * Converter from mp-int to long
	 */
	enum MpIntToLong
		implements MpToStackConv<TInt, IntJitType, MpIntJitType, TLong, LongJitType> {
		INSTANCE;

		@Override
		public <N extends Next> Emitter<Ent<N, TLong>> convertOpndToStack(Emitter<N> em,
				Opnd<MpIntJitType> from, LongJitType to, Ext ext) {
			var legs = from.type().castLegsLE(from);
			return em
					.emit(legs.get(1)::read)
					.emit(legs.get(0)::read)
					.emit(Op::invokestatic, GenConsts.T_JIT_COMPILED_PASSAGE, "conv2IntToLong",
						GenConsts.MDESC_JIT_COMPILED_PASSAGE__CONV_OFFSET2_TO_LONG, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(LongToLong.INSTANCE::convertStackToStack, LongJitType.I8, to, ext);
		}

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<Ent<N1, TLong>>
				convertArrayToStack(Emitter<N0> em, MpIntJitType from, LongJitType to, Ext ext) {
			return em
					.emit(Op::dup)
					.emit(Op::ldc__i, 1)
					.emit(Op::iaload)
					.emit(Op::swap)
					.emit(Op::ldc__i, 0)
					.emit(Op::iaload)
					.emit(Op::invokestatic, GenConsts.T_JIT_COMPILED_PASSAGE, "conv2IntToLong",
						GenConsts.MDESC_JIT_COMPILED_PASSAGE__CONV_OFFSET2_TO_LONG, true)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(LongToLong.INSTANCE::convertStackToStack, LongJitType.I8, to, ext);
		}
	}

	/**
	 * Converter from mp-int to mp-int
	 */
	enum MpIntToMpInt
		implements MpToMpConv<TInt, IntJitType, MpIntJitType, TInt, IntJitType, MpIntJitType> {
		INSTANCE;

		@Override
		public <N extends Next> OpndEm<MpIntJitType, N> convertOpndToOpnd(Emitter<N> em,
				Opnd<MpIntJitType> from, MpIntJitType to, Ext ext, Scope scope) {
			if (to.size() == from.type().size()) {
				return new OpndEm<>(from, em);
			}
			List<SimpleOpnd<TInt, IntJitType>> fromLegs = from.type().castLegsLE(from);
			List<IntJitType> toLegTypes = to.legTypesLE();
			int legsIn = from.legsLE().size();
			int legsOut = to.legsAlloc();
			int defLegs = Integer.min(legsIn, legsOut);

			List<SimpleOpnd<TInt, IntJitType>> toLegs = new ArrayList<>();
			for (int i = 0; i < defLegs; i++) {
				var curLeg = fromLegs.get(i);
				toLegs.add(switch (curLeg) {
					case IntReadOnlyLocalOpnd ro when ext == Ext.SIGN -> ro;
					case IntConstOpnd c when ext == Ext.ZERO -> c;
					default -> {
						if (!needsIntExt(curLeg.type(), toLegTypes.get(i))) {
							yield curLeg;
						}
						String name = "%s_convLeg%d".formatted(from.name(), i);
						var result = em
								.emit(curLeg::read)
								.emit(Opnd::convertIntToInt, IntJitType.I4, curLeg.type(), ext)
								.emit(Opnd::convertIntToInt, curLeg.type(), toLegTypes.get(i), ext)
								.emit(Opnd::createInt, toLegTypes.get(i), name, scope);
						em = result.em();
						yield result.opnd();
					}
				});
			}
			if (legsOut > defLegs) {
				var sign = switch (ext) {
					case ZERO -> new SimpleOpndEm<>(IntConstOpnd.ZERO_I4, em);
					case SIGN -> switch (toLegs.getLast()) {
						case IntConstOpnd c -> new SimpleOpndEm<>(c, em);
						default -> em
								.emit(toLegs.getLast()::read)
								.emit(Op::ldc__i, Integer.SIZE - 1)
								.emit(Op::ishr) // Signed
								.emit(Opnd::createIntReadOnly, IntJitType.I4,
									"%s_sign".formatted(from.name()), scope);
					};
				};
				em = sign.em();
				for (int i = defLegs; i < legsOut; i++) {
					toLegs.add(sign.opnd());
				}
			}
			return new OpndEm<>(
				MpIntLocalOpnd.of(to, "%s_convMpInt".formatted(from.name()), toLegs), em);
		}

		/**
		 * Emit code that extends a value to fill the rest of an array
		 * <p>
		 * For sign extension, this will assume the last filled element of the array so far is the
		 * leg having the sign bit. It shifts and extends that bit to fill a new temporary leg and
		 * uses it to fill the remaining more-significant legs. NOTE: {@code legsOut} may be less
		 * than the actual size of the array, since slack elements may have been allocated.
		 * 
		 * @param <N> the tail of the stack (...)
		 * @param em the emitter
		 * @param arr a handle to the local containing the array
		 * @param legsOut the number of output legs
		 * @param defLegs the number of legs already filled
		 * @param ext the kind of extension to apply
		 * @param scope a scope for generated temporary variables
		 * @return the emitter with ...
		 */
		public static <N extends Next> Emitter<N> doGenArrExt(Emitter<N> em, Local<TRef<int[]>> arr,
				int legsOut, int defLegs, Ext ext, Scope scope) {
			if (legsOut <= defLegs) {
				return em;
			}
			return switch (ext) {
				case ZERO -> em; // Uninitialized array elements are already 0
				case SIGN -> {
					try (SubScope ss = scope.sub()) {
						Local<TInt> sign = ss.decl(Types.T_INT, "temp_sign");
						em = em
								.emit(Op::aload, arr)
								.emit(Op::ldc__i, defLegs - 1)
								.emit(Op::iaload)
								.emit(Op::ldc__i, Integer.SIZE - 1)
								.emit(Op::ishr)
								.emit(Op::istore, sign);
						for (int i = defLegs; i < legsOut; i++) {
							em = em
									.emit(Op::aload, arr)
									.emit(Op::ldc__i, i)
									.emit(Op::iload, sign)
									.emit(Op::iastore);
						}
						yield em;
					}
				}
			};
		}

		@Override
		public <N extends Next> Emitter<Ent<N, TRef<int[]>>> convertOpndToArray(Emitter<N> em,
				Opnd<MpIntJitType> from, MpIntJitType to, Ext ext, Scope scope, int slack) {
			List<SimpleOpnd<TInt, IntJitType>> fromLegs = from.type().castLegsLE(from);
			List<IntJitType> toLegTypes = to.legTypesLE();
			int legsIn = from.type().legsAlloc();
			int legsOut = to.legsAlloc();
			int defLegs = Integer.min(legsIn, legsOut);

			Local<TRef<int[]>> arr =
				scope.decl(Types.T_INT_ARR, "%s_convArr".formatted(from.name()));
			em = em
					.emit(Op::ldc__i, legsOut + slack)
					.emit(Op::newarray, Types.T_INT)
					.emit(Op::astore, arr);

			for (int i = 0; i < defLegs; i++) {
				SimpleOpnd<TInt, IntJitType> fromLeg = fromLegs.get(i);
				IntJitType toLegType = toLegTypes.get(i);
				em = em
						.emit(Op::aload, arr)
						.emit(Op::ldc__i, i)
						.emit(fromLeg::read)
						.emit(Opnd::convertIntToInt, fromLeg.type(), toLegType, ext)
						.emit(Op::iastore);
			}
			return em
					.emit(MpIntToMpInt::doGenArrExt, arr, legsOut, defLegs, ext, scope)
					.emit(Op::aload, arr);
		}
	}

	/**
	 * Converter from mp-int to (simple) float
	 */
	enum MpIntToFloat
		implements MpToStackConv<TInt, IntJitType, MpIntJitType, TFloat, FloatJitType> {
		INSTANCE;

		@Override
		public <N extends Next> Emitter<Ent<N, TFloat>> convertOpndToStack(Emitter<N> em,
				Opnd<MpIntJitType> from, FloatJitType to, Ext ext) {
			return em
					.emit(MpIntToInt.INSTANCE::convertOpndToStack, from, IntJitType.I4, ext)
					.emit(IntToFloat.INSTANCE::convertStackToStack, IntJitType.I4, to, ext);
		}

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<Ent<N1, TFloat>>
				convertArrayToStack(Emitter<N0> em, MpIntJitType from, FloatJitType to, Ext ext) {
			return em
					.emit(MpIntToInt.INSTANCE::convertArrayToStack, from, IntJitType.I4, ext)
					.emit(IntToFloat.INSTANCE::convertStackToStack, IntJitType.I4, to, ext);
		}
	}

	/**
	 * Converter from mp-int to double
	 */
	enum MpIntToDouble
		implements MpToStackConv<TInt, IntJitType, MpIntJitType, TDouble, DoubleJitType> {
		INSTANCE;

		@Override
		public <N extends Next> Emitter<Ent<N, TDouble>> convertOpndToStack(Emitter<N> em,
				Opnd<MpIntJitType> from, DoubleJitType to, Ext ext) {
			return em
					.emit(MpIntToLong.INSTANCE::convertOpndToStack, from, LongJitType.I8, ext)
					.emit(LongToDouble.INSTANCE::convertStackToStack, LongJitType.I8, to, ext);
		}

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<Ent<N1, TDouble>>
				convertArrayToStack(Emitter<N0> em, MpIntJitType from, DoubleJitType to, Ext ext) {
			return em
					.emit(MpIntToLong.INSTANCE::convertArrayToStack, from, LongJitType.I8, ext)
					.emit(LongToDouble.INSTANCE::convertStackToStack, LongJitType.I8, to, ext);
		}
	}

	/**
	 * Converter from float to int
	 */
	enum FloatToInt implements StackToStackConv<TFloat, FloatJitType, TInt, IntJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TFloat>> Emitter<Ent<N1, TInt>>
				convertStackToStack(Emitter<N0> em, FloatJitType from, IntJitType to, Ext ext) {
			if (to.size() != from.size()) {
				throw new AssertionError("Size mismatch");
			}
			return em
					.emit(Op::invokestatic, GenConsts.TR_FLOAT, "floatToRawIntBits",
						GenConsts.MDESC_FLOAT__FLOAT_TO_RAW_INT_BITS, false)
					.step(Inv::takeArg)
					.step(Inv::ret);
		}
	}

	/**
	 * Converter from float to long
	 */
	enum FloatToLong implements StackToStackConv<TFloat, FloatJitType, TLong, LongJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TFloat>> Emitter<Ent<N1, TLong>>
				convertStackToStack(Emitter<N0> em, FloatJitType from, LongJitType to, Ext ext) {
			return em
					.emit(FloatToInt.INSTANCE::convertStackToStack, from, IntJitType.I4, ext)
					.emit(IntToLong.INSTANCE::convertStackToStack, IntJitType.I4, to, ext);
		}
	}

	/**
	 * Converter from float to mp-int
	 */
	enum FloatToMpInt
		implements StackToMpConv<TFloat, FloatJitType, TInt, IntJitType, MpIntJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TFloat>> OpndEm<MpIntJitType, N1>
				convertStackToOpnd(Emitter<N0> em, FloatJitType from, String name, MpIntJitType to,
						Ext ext, Scope scope) {
			return em
					.emit(FloatToInt.INSTANCE::convertStackToStack, from, IntJitType.I4, ext)
					.emit(IntToMpInt.INSTANCE::convertStackToOpnd, IntJitType.I4, name, to, ext,
						scope);
		}

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TFloat>> Emitter<Ent<N1, TRef<int[]>>>
				convertStackToArray(Emitter<N0> em, FloatJitType from, String name, MpIntJitType to,
						Ext ext, Scope scope, int slack) {
			return em
					.emit(FloatToInt.INSTANCE::convertStackToStack, from, IntJitType.I4, ext)
					.emit(IntToMpInt.INSTANCE::convertStackToArray, IntJitType.I4, name, to, ext,
						scope, slack);
		}
	}

	/**
	 * Converter from float to float
	 */
	enum FloatToFloat implements StackToStackConv<TFloat, FloatJitType, TFloat, FloatJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TFloat>> Emitter<Ent<N1, TFloat>>
				convertStackToStack(Emitter<N0> em, FloatJitType from, FloatJitType to, Ext ext) {
			return em.emit(Misc::cast1);
		}
	}

	/**
	 * Converter from float to double
	 */
	enum FloatToDouble implements StackToStackConv<TFloat, FloatJitType, TDouble, DoubleJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TFloat>> Emitter<Ent<N1, TDouble>>
				convertStackToStack(Emitter<N0> em, FloatJitType from, DoubleJitType to, Ext ext) {
			return em
					.emit(FloatToInt.INSTANCE::convertStackToStack, from, IntJitType.I4, ext)
					.emit(IntToDouble.INSTANCE::convertStackToStack, IntJitType.I4, to, ext);
		}
	}

	/**
	 * Converter from double to int
	 */
	enum DoubleToInt implements StackToStackConv<TDouble, DoubleJitType, TInt, IntJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TDouble>> Emitter<Ent<N1, TInt>>
				convertStackToStack(Emitter<N0> em, DoubleJitType from, IntJitType to, Ext ext) {
			return em
					.emit(DoubleToLong.INSTANCE::convertStackToStack, from, LongJitType.I8, ext)
					.emit(LongToInt.INSTANCE::convertStackToStack, LongJitType.I8, to, ext);
		}
	}

	/**
	 * Converter from double to long
	 */
	enum DoubleToLong implements StackToStackConv<TDouble, DoubleJitType, TLong, LongJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TDouble>> Emitter<Ent<N1, TLong>>
				convertStackToStack(Emitter<N0> em, DoubleJitType from, LongJitType to, Ext ext) {
			if (to.size() != from.size()) {
				throw new AssertionError("Size mismatch");
			}
			return em
					.emit(Op::invokestatic, GenConsts.TR_DOUBLE, "doubleToRawLongBits",
						GenConsts.MDESC_DOUBLE__DOUBLE_TO_RAW_LONG_BITS, false)
					.step(Inv::takeArg)
					.step(Inv::ret);
		}
	}

	/**
	 * Converter from double to mp-int
	 */
	enum DoubleToMpInt
		implements StackToMpConv<TDouble, DoubleJitType, TInt, IntJitType, MpIntJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TDouble>> OpndEm<MpIntJitType, N1>
				convertStackToOpnd(Emitter<N0> em, DoubleJitType from, String name, MpIntJitType to,
						Ext ext, Scope scope) {
			return em
					.emit(DoubleToLong.INSTANCE::convertStackToStack, from, LongJitType.I8, ext)
					.emit(LongToMpInt.INSTANCE::convertStackToOpnd, LongJitType.I8, name, to, ext,
						scope);
		}

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TDouble>> Emitter<Ent<N1, TRef<int[]>>>
				convertStackToArray(Emitter<N0> em, DoubleJitType from, String name,
						MpIntJitType to, Ext ext, Scope scope, int slack) {
			return em
					.emit(DoubleToLong.INSTANCE::convertStackToStack, from, LongJitType.I8, ext)
					.emit(LongToMpInt.INSTANCE::convertStackToArray, LongJitType.I8, name, to, ext,
						scope, slack);
		}
	}

	/**
	 * Converter from double to float
	 */
	enum DoubleToFloat implements StackToStackConv<TDouble, DoubleJitType, TFloat, FloatJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TDouble>> Emitter<Ent<N1, TFloat>>
				convertStackToStack(Emitter<N0> em, DoubleJitType from, FloatJitType to, Ext ext) {
			return em
					.emit(DoubleToInt.INSTANCE::convertStackToStack, from, IntJitType.I4, ext)
					.emit(IntToFloat.INSTANCE::convertStackToStack, IntJitType.I4, to, ext);
		}
	}

	/**
	 * Converter from double to double
	 */
	enum DoubleToDouble
		implements StackToStackConv<TDouble, DoubleJitType, TDouble, DoubleJitType> {
		INSTANCE;

		@Override
		public <N1 extends Next, N0 extends Ent<N1, TDouble>> Emitter<Ent<N1, TDouble>>
				convertStackToStack(Emitter<N0> em, DoubleJitType from, DoubleJitType to, Ext ext) {
			return em.emit(Misc::cast1);
		}
	}

	/**
	 * Create a constant int operand of the given type
	 * 
	 * @param type the p-code type
	 * @param value the value
	 * @return the constant
	 */
	public static SimpleOpnd<TInt, IntJitType> constOf(IntJitType type, int value) {
		if (value == 0) {
			return IntConstOpnd.zero(type);
		}
		return new IntConstOpnd(value, type);
	}

	/**
	 * Create a constant long operand of the given type
	 * 
	 * @param type the p-code type
	 * @param value the value
	 * @return the constant
	 */
	public static SimpleOpnd<TLong, LongJitType> constOf(LongJitType type, long value) {
		return new LongConstOpnd(value, type);
	}

	/**
	 * Create a constant float operand of the given type
	 * 
	 * @param type the p-code type
	 * @param value the value
	 * @return the constant
	 */
	public static SimpleOpnd<TFloat, FloatJitType> constOf(FloatJitType type, float value) {
		return new FloatConstOpnd(value, type);
	}

	/**
	 * Create a constant double operand of the given type
	 * 
	 * @param type the p-code type
	 * @param value the value
	 * @return the constant
	 */
	public static SimpleOpnd<TDouble, DoubleJitType> constOf(DoubleJitType type, double value) {
		return new DoubleConstOpnd(value, type);
	}

	/**
	 * Create a constant mp-int operand of the given type
	 * 
	 * @param type the p-code type
	 * @param value the value
	 * @return the constant
	 */
	public static Opnd<MpIntJitType> constOf(MpIntJitType type, BigInteger value) {
		return new MpIntConstOpnd(value, type);
	}

	/**
	 * Emit code to convert a simple int to a boolean
	 * <p>
	 * This treats any non-zero value as true. Only zero is treated as false. The result is either 1
	 * (true) or 0 (false). In other words, this converts any non-zero value to 1. Zero is left as
	 * 0.
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return ..., result
	 */
	public static <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>> intToBool(
			Emitter<N0> em) {
		var lblTrue = em
				.emit(Op::ifne);
		var lblDone = lblTrue.em()
				.emit(Op::ldc__i, 0)
				.emit(Op::goto_);
		return lblDone.em()
				.emit(Lbl::placeDead, lblTrue.lbl())
				.emit(Op::ldc__i, 1)
				.emit(Lbl::place, lblDone.lbl());
	}

	/**
	 * Emit nothing, but cast the emitter by asserting two given p-code types are identical
	 * <p>
	 * This is often used in switch statements where the cases are specific types. Likely the switch
	 * variable has a generic type. For a given case, we know that generic type is identical to a
	 * given p-code type, but to convince the Java compiler, we need to cast. This method provides a
	 * structured mechanism for that cast to prevent mistakes. Additionally, at runtime, if
	 * assertions are enabled, this will fail when the given types are not actually identical.
	 * 
	 * @param <TT> the "to" JVM type
	 * @param <TJT> the "to" p-code type
	 * @param <FT> the "from" JVM type
	 * @param <FJT> the "from" p-code type
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param from the p-code type
	 * @param to the same p-code type, but with an apparently different type at compile time
	 * @return the emitter with ..., value (unchanged)
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static <
		TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>,
		FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>,
		N1 extends Next, N0 extends Ent<N1, FT>>
			Emitter<Ent<N1, TT>> castStack1(Emitter<N0> em, FJT from, TJT to) {
		assert from == to;
		return (Emitter) em;
	}

	/**
	 * Create an operand of the given p-code type from the value on the stack
	 * 
	 * @param <T> the JVM type
	 * @param <JT> the p-code type
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param type the p-code type
	 * @param name the name of the local variable to create
	 * @param scope a scope for the local variable
	 * @return the operand and emitter with ...
	 */
	public static <
		T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N1 extends Next, N0 extends Ent<N1, T>>
			SimpleOpndEm<T, JT, N1> create(Emitter<N0> em, JT type, String name, Scope scope) {
		return switch (type) {
			case IntJitType t -> IntLocalOpnd.create(castStack1(em, type, t), t, name, scope)
					.castBack(type);
			case LongJitType t -> LongLocalOpnd.create(castStack1(em, type, t), t, name, scope)
					.castBack(type);
			case FloatJitType t -> FloatLocalOpnd.create(castStack1(em, type, t), t, name, scope)
					.castBack(type);
			case DoubleJitType t -> DoubleLocalOpnd.create(castStack1(em, type, t), t, name, scope)
					.castBack(type);
			default -> throw new AssertionError();
		};
	}

	/**
	 * Create an int operand from the value on the stack
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param type the p-code type
	 * @param name the name of the local variable to create
	 * @param scope a scope for the local variable
	 * @return the operand and emitter with ...
	 */
	public static <N1 extends Next, N0 extends Ent<N1, TInt>> SimpleOpndEm<TInt, IntJitType, N1>
			createInt(Emitter<N0> em, IntJitType type, String name, Scope scope) {
		return IntLocalOpnd.create(em, type, name, scope);
	}

	/**
	 * Create a read-only int operand from the value on the stack
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param type the p-code type
	 * @param name the name of the local variable to create
	 * @param scope a scope for the local variable
	 * @return the operand and emitter with ...
	 * @see SimpleOpnd#ofIntReadOnly(IntJitType, Local)
	 */
	public static <N1 extends Next, N0 extends Ent<N1, TInt>> SimpleOpndEm<TInt, IntJitType, N1>
			createIntReadOnly(Emitter<N0> em, IntJitType type, String name, Scope scope) {
		return IntReadOnlyLocalOpnd.create(em, type, name, scope);
	}

	/**
	 * Obtain the converter between two given simple types
	 * 
	 * @param <FT> the "from" JVM type
	 * @param <FJT> the "from" p-code type
	 * @param <TT> the "to" JVM type
	 * @param <TJT> the "to" p-code type
	 * @param from the source p-code type
	 * @param to the destination p-code type
	 * @return the converter
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	static <
		FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>,
		TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>>
			StackToStackConv<FT, FJT, TT, TJT> getStackToStack(FJT from, TJT to) {
		return (StackToStackConv) switch (from) {
			case IntJitType ft -> switch (to) {
				case IntJitType tt -> IntToInt.INSTANCE;
				case LongJitType tt -> IntToLong.INSTANCE;
				case FloatJitType tt -> IntToFloat.INSTANCE;
				case DoubleJitType tt -> IntToDouble.INSTANCE;
				default -> throw new AssertionError();
			};
			case LongJitType ft -> switch (to) {
				case IntJitType tt -> LongToInt.INSTANCE;
				case LongJitType tt -> LongToLong.INSTANCE;
				case FloatJitType tt -> LongToFloat.INSTANCE;
				case DoubleJitType tt -> LongToDouble.INSTANCE;
				default -> throw new AssertionError();
			};
			case FloatJitType ft -> switch (to) {
				case IntJitType tt -> FloatToInt.INSTANCE;
				case LongJitType tt -> FloatToLong.INSTANCE;
				case FloatJitType tt -> FloatToFloat.INSTANCE;
				case DoubleJitType tt -> FloatToDouble.INSTANCE;
				default -> throw new AssertionError();
			};
			case DoubleJitType ft -> switch (to) {
				case IntJitType tt -> DoubleToInt.INSTANCE;
				case LongJitType tt -> DoubleToLong.INSTANCE;
				case FloatJitType tt -> DoubleToFloat.INSTANCE;
				case DoubleJitType tt -> DoubleToDouble.INSTANCE;
				default -> throw new AssertionError();
			};
			default -> throw new AssertionError();
		};
	}

	/**
	 * Convert from a given simple type to another simple type
	 * 
	 * @param <FT> the "from" JVM type
	 * @param <FJT> the "from" p-code type
	 * @param <TT> the "to" JVM type
	 * @param <TJT> the "to" p-code type
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param from the source p-code type
	 * @param to the destination p-code type
	 * @param ext the kind of extension to apply
	 * @return the emitter with ..., result
	 */
	public static <
		FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>,
		TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>,
		N1 extends Next, N0 extends Ent<N1, FT>>
			Emitter<Ent<N1, TT>> convert(Emitter<N0> em, FJT from, TJT to, Ext ext) {
		return getStackToStack(from, to).convertStackToStack(em, from, to, ext);
	}

	/**
	 * Convert from an int type to another int type
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param from the source p-code type
	 * @param to the destination p-code type
	 * @param ext the kind of extension to apply
	 * @return the emitter with ..., result
	 */
	public static <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>>
			convertIntToInt(Emitter<N0> em, IntJitType from, IntJitType to, Ext ext) {
		return IntToInt.INSTANCE.convertStackToStack(em, from, to, ext);
	}

	/**
	 * Obtain the converter from a simple type to an mp type
	 * 
	 * @param <FT> the "from" JVM type
	 * @param <FJT> the "from" p-code type
	 * @param <TT> the "to" JVM type for each mp leg
	 * @param <TLT> the "to" p-code type for each mp leg
	 * @param <TJT> the "to" p-code type
	 * @param from the source p-code type
	 * @param to the destination p-code type
	 * @return the converter
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	static <
		FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>,
		TT extends BPrim<?>, TLT extends SimpleJitType<TT, TLT>,
		TJT extends LeggedJitType<TT, TLT>>
			StackToMpConv<FT, FJT, TT, TLT, TJT> getStackToMp(FJT from, TJT to) {
		return (StackToMpConv) switch (from) {
			case IntJitType ft -> switch (to) {
				case MpIntJitType tt -> IntToMpInt.INSTANCE;
				default -> throw new AssertionError();
			};
			case LongJitType ft -> switch (to) {
				case MpIntJitType tt -> LongToMpInt.INSTANCE;
				default -> throw new AssertionError();
			};
			case FloatJitType ft -> switch (to) {
				case MpIntJitType tt -> FloatToMpInt.INSTANCE;
				default -> throw new AssertionError();
			};
			case DoubleJitType ft -> switch (to) {
				case MpIntJitType tt -> DoubleToMpInt.INSTANCE;
				default -> throw new AssertionError();
			};
			default -> throw new AssertionError();
		};
	}

	/**
	 * Convert from a simple type to an mp type in local variables
	 * 
	 * @param <FT> the "from" JVM type
	 * @param <FJT> the "from" p-code type
	 * @param <TT> the "to" JVM type for each mp leg
	 * @param <TLT> the "to" p-code type for each mp leg
	 * @param <TJT> the "to" p-code type
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param from the source p-code type
	 * @param name a name (prefix) for the mp-int
	 * @param to the destination p-code type
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generated variables
	 * @return the resulting operand and emitter with ...
	 */
	public static <
		FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>,
		TT extends BPrim<?>, TLT extends SimpleJitType<TT, TLT>,
		TJT extends LeggedJitType<TT, TLT>,
		N1 extends Next, N0 extends Ent<N1, FT>>
			OpndEm<TJT, N1>
			convertToOpnd(Emitter<N0> em, FJT from, String name, TJT to, Ext ext, Scope scope) {
		return getStackToMp(from, to).convertStackToOpnd(em, from, name, to, ext, scope);
	}

	/**
	 * Convert from a simple type to an mp type in an array
	 * 
	 * @param <FT> the "from" JVM type
	 * @param <FJT> the "from" p-code type
	 * @param <TT> the "to" JVM type for each mp leg
	 * @param <TLT> the "to" p-code type for each mp leg
	 * @param <TJT> the "to" p-code type
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param from the source p-code type
	 * @param name a name (prefix) for the mp-int
	 * @param to the destination p-code type
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generated variables
	 * @param slack the number of extra (more significant) elements to allocate in the array
	 * @return the emitter with ..., arrayref
	 */
	public static <
		FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>,
		TT extends BPrim<?>, TLT extends SimpleJitType<TT, TLT>,
		TJT extends LeggedJitType<TT, TLT>,
		N1 extends Next, N0 extends Ent<N1, FT>>
			Emitter<Ent<N1, TRef<int[]>>> convertToArray(Emitter<N0> em, FJT from, String name,
					TJT to, Ext ext, Scope scope, int slack) {
		return getStackToMp(from, to).convertStackToArray(em, from, name, to, ext, scope, slack);
	}

	/**
	 * Kinds of extension
	 */
	enum Ext {
		/** Zero extension */
		ZERO,
		/** Sign extension */
		SIGN;

		/**
		 * Get the extension based on signedness
		 * 
		 * @param signed true for signed, false for unsigned
		 * @return the kind of extension
		 */
		public static Ext forSigned(boolean signed) {
			return signed ? SIGN : ZERO;
		}
	}

	/**
	 * {@return the p-code type}
	 */
	T type();

	/**
	 * {@return the name}
	 */
	String name();

	/**
	 * {@return the legs in little-endian order}
	 * <p>
	 * For non-legged types, this returns the singleton list containing only this operand
	 */
	List<? extends SimpleOpnd<?, ?>> legsLE();
}
