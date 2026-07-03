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
package ghidra.pcode.emu.jit.gen;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import org.objectweb.asm.Type;

import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.emu.jit.*;
import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.ExitSlot;
import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Methods.MthDesc;
import ghidra.pcode.emu.jit.gen.util.Types;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Various constants (namely class names, type descriptions, method descriptions, etc. used during
 * bytecode generation.
 */
@SuppressWarnings("javadoc")
public interface GenConsts {
	public static final int BLOCK_SIZE = SemisparseByteArray.BLOCK_SIZE;

	public static final TRef<Object[]> TARR_OBJECT = Types.refOf(Object[].class);
	public static final TRef<Varnode[]> TARR_VARNODE = Types.refOf(Varnode[].class);
	public static final TRef<Double> TR_DOUBLE = Types.refOf(Double.class);
	public static final TRef<Float> TR_FLOAT = Types.refOf(Float.class);
	public static final TRef<Integer> TR_INTEGER = Types.refOf(Integer.class);
	public static final TRef<Long> TR_LONG = Types.refOf(Long.class);
	public static final TRef<Address> T_ADDRESS = Types.refOf(Address.class);
	public static final TRef<AddressFactory> T_ADDRESS_FACTORY =
		Types.refOf(AddressFactory.class);
	public static final TRef<AddressSpace> T_ADDRESS_SPACE = Types.refOf(AddressSpace.class);
	public static final TRef<AddrCtx> T_ADDR_CTX = Types.refOf(AddrCtx.class);
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static final TRef<ArrayList<?>> T_ARRAY_LIST = (TRef) Types.refOf(ArrayList.class);
	public static final TRef<AssertionError> T_ASSERTION_ERROR =
		Types.refOf(AssertionError.class);
	public static final TRef<DecodePcodeExecutionException> T_DECODE_PCODE_EXECUTION_EXCEPTION =
		Types.refOf(DecodePcodeExecutionException.class);
	public static final TRef<EntryPoint> T_ENTRY_POINT = Types.refOf(EntryPoint.class);
	public static final TRef<ExitSlot> T_EXIT_SLOT = Types.refOf(ExitSlot.class);
	public static final TRef<IllegalArgumentException> T_ILLEGAL_ARGUMENT_EXCEPTION =
		Types.refOf(IllegalArgumentException.class);
	public static final TRef<JitBytesPcodeExecutorState> T_JIT_BYTES_PCODE_EXECUTOR_STATE =
		Types.refOf(JitBytesPcodeExecutorState.class);
	public static final TRef<JitBytesPcodeExecutorStateSpace> //
	T_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE = Types.refOf(JitBytesPcodeExecutorStateSpace.class);
	public static final TRef<JitCompiledPassage> T_JIT_COMPILED_PASSAGE =
		Types.refOf(JitCompiledPassage.class);
	public static final TRef<JitPcodeThread> T_JIT_PCODE_THREAD =
		Types.refOf(JitPcodeThread.class);
	public static final TRef<JitThreadBytesPcodeExecutorState> //
	T_JIT_THREAD_BYTES_PCODE_EXECUTOR_STATE = Types.refOf(JitThreadBytesPcodeExecutorState.class);
	public static final TRef<Language> T_LANGUAGE = Types.refOf(Language.class);
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static final TRef<List<?>> T_LIST = (TRef) Types.refOf(List.class);
	public static final TRef<LowlevelError> T_LOWLEVEL_ERROR = Types.refOf(LowlevelError.class);
	public static final TRef<Math> T_MATH = Types.refOf(Math.class);
	public static final TRef<Object> T_OBJECT = Types.refOf(Object.class);
	public static final TRef<PcodeOp> T_PCODE_OP = Types.refOf(PcodeOp.class);
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static final TRef<PcodeUseropDefinition<?>> T_PCODE_USEROP_DEFINITION =
		(TRef) Types.refOf(PcodeUseropDefinition.class);
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static final TRef<PcodeUseropDefinition<byte[]>> T_PCODE_USEROP_DEFINITION__BYTEARR =
		(TRef) T_PCODE_USEROP_DEFINITION;
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static final TRef<PcodeUseropLibrary<?>> T_PCODE_USEROP_LIBRARY =
		(TRef) Types.refOf(PcodeUseropLibrary.class);
	public static final TRef<PrintStream> T_PRINT_STREAM = Types.refOf(PrintStream.class);
	public static final TRef<RegisterValue> T_REGISTER_VALUE = Types.refOf(RegisterValue.class);
	public static final TRef<SleighLinkException> T_SLEIGH_LINK_EXCEPTION =
		Types.refOf(SleighLinkException.class);
	public static final TRef<String> T_STRING = Types.refOf(String.class);
	public static final TRef<System> T_SYSTEM = Types.refOf(System.class);
	public static final TRef<Throwable> T_THROWABLE = Types.refOf(Throwable.class);
	public static final TRef<Varnode> T_VARNODE = Types.refOf(Varnode.class);

	public static final MthDesc<TVoid,
		Ent<Ent<Bot, TRef<RegisterValue>>, TRef<Address>>> MDESC_ADDR_CTX__$INIT =
			MthDesc.returns(Types.T_VOID).param(T_REGISTER_VALUE).param(T_ADDRESS).build();
	public static final MthDesc<TRef<AddressSpace>,
		Ent<Bot, TInt>> MDESC_ADDRESS_FACTORY__GET_ADDRESS_SPACE =
			MthDesc.returns(T_ADDRESS_SPACE).param(Types.T_INT).build();
	public static final MthDesc<TRef<Address>, Ent<Bot, TLong>> MDESC_ADDRESS_SPACE__GET_ADDRESS =
		MthDesc.returns(T_ADDRESS).param(Types.T_LONG).build();
	public static final MthDesc<TVoid, Bot> MDESC_ARRAY_LIST__$INIT =
		MthDesc.returns(Types.T_VOID).build();
	// NOTE: The void (String) form is private....
	public static final MthDesc<TVoid, Ent<Bot, TRef<Object>>> MDESC_ASSERTION_ERROR__$INIT =
		MthDesc.returns(Types.T_VOID).param(T_OBJECT).build();
	public static final MthDesc<TLong, Ent<Bot, TDouble>> MDESC_DOUBLE__DOUBLE_TO_RAW_LONG_BITS =
		MthDesc.returns(Types.T_LONG).param(Types.T_DOUBLE).build();
	public static final MthDesc<TInt, Ent<Bot, TDouble>> MDESC_DOUBLE__IS_NAN =
		MthDesc.<Boolean, Double> derive(d -> Double.isNaN(d))
				.check(MthDesc::returns, Types.T_BOOL)
				.check(MthDesc::param, Types.T_DOUBLE)
				.check(MthDesc::build);
	public static final MthDesc<TDouble, Ent<Bot, TLong>> MDESC_DOUBLE__LONG_BITS_TO_DOUBLE =
		MthDesc.returns(Types.T_DOUBLE).param(Types.T_LONG).build();
	public static final MthDesc<TInt, Ent<Bot, TFloat>> MDESC_FLOAT__FLOAT_TO_RAW_INT_BITS =
		MthDesc.returns(Types.T_INT).param(Types.T_FLOAT).build();
	public static final MthDesc<TFloat, Ent<Bot, TInt>> MDESC_FLOAT__INT_BITS_TO_FLOAT =
		MthDesc.returns(Types.T_FLOAT).param(Types.T_INT).build();
	public static final MthDesc<TInt, Ent<Bot, TFloat>> MDESC_FLOAT__IS_NAN =
		MthDesc.<Boolean, Float> derive(d -> Float.isNaN(d))
				.check(MthDesc::returns, Types.T_BOOL)
				.check(MthDesc::param, Types.T_FLOAT)
				.check(MthDesc::build);
	public static final MthDesc<TVoid,
		Ent<Bot, TRef<String>>> MDESC_ILLEGAL_ARGUMENT_EXCEPTION__$INIT =
			MthDesc.returns(Types.T_VOID).param(T_STRING).build();
	public static final MthDesc<TInt, Ent<Bot, TInt>> MDESC_INTEGER__BIT_COUNT =
		MthDesc.derive(Integer::bitCount)
				.check(MthDesc::returns, Types.T_INT)
				.check(MthDesc::param, Types.T_INT)
				.check(MthDesc::build);
	public static final MthDesc<TInt, Ent<Ent<Bot, TInt>, TInt>> MDESC_INTEGER__COMPARE =
		MthDesc.returns(Types.T_INT).param(Types.T_INT).param(Types.T_INT).build();
	public static final MthDesc<TInt, Ent<Bot, TInt>> MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS =
		MthDesc.derive(Integer::numberOfLeadingZeros)
				.check(MthDesc::returns, Types.T_INT)
				.check(MthDesc::param, Types.T_INT)
				.check(MthDesc::build);
	public static final MthDesc<TLong, Ent<Bot, TInt>> MDESC_INTEGER__TO_UNSIGNED_LONG =
		MthDesc.returns(Types.T_LONG).param(Types.T_INT).build();
	public static final MthDesc<TRef<Integer>, Ent<Bot, TInt>> MDESC_INTEGER__VALUE_OF =
		MthDesc.returns(TR_INTEGER).param(Types.T_INT).build();
	public static final String MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE__GET_LANGUAGE =
		Type.getMethodDescriptor(Type.getType(Language.class));
	public static final MthDesc<TRef<JitBytesPcodeExecutorStateSpace>,
		Ent<Bot, TRef<AddressSpace>>> MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE__GET_SPACE_FOR =
			MthDesc.returns(T_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE).param(T_ADDRESS_SPACE).build();
	public static final MthDesc<TRef<byte[]>,
		Ent<Bot, TLong>> MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__GET_DIRECT =
			MthDesc.returns(Types.T_BYTE_ARR).param(Types.T_LONG).build();
	public static final MthDesc<TRef<byte[]>,
		Ent<Ent<Bot, TLong>, TInt>> MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__READ =
			MthDesc.returns(Types.T_BYTE_ARR).param(Types.T_LONG).param(Types.T_INT).build();
	public static final MthDesc<TVoid,
		Ent<Ent<Ent<Ent<Bot, TLong>, TRef<byte[]>>, TInt>,
			TInt>> MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__WRITE =
				MthDesc.returns(Types.T_VOID)
						.param(Types.T_LONG)
						.param(Types.T_BYTE_ARR)
						.param(Types.T_INT)
						.param(Types.T_INT)
						.build();
	public static final MthDesc<TLong,
		Ent<Ent<Bot, TInt>, TInt>> MDESC_JIT_COMPILED_PASSAGE__CONV_OFFSET2_TO_LONG =
			MthDesc.returns(Types.T_LONG).param(Types.T_INT).param(Types.T_INT).build();
	public static final MthDesc<TVoid,
		Ent<Ent<Bot, TInt>, TInt>> MDESC_JIT_COMPILED_PASSAGE__COUNT =
			MthDesc.returns(Types.T_VOID).param(Types.T_INT).param(Types.T_INT).build();
	public static final MthDesc<TRef<RegisterValue>,
		Ent<Ent<Bot, TRef<Language>>, TRef<String>>> MDESC_JIT_COMPILED_PASSAGE__CREATE_CONTEXT =
			MthDesc.returns(T_REGISTER_VALUE).param(T_LANGUAGE).param(T_STRING).build();
	public static final MthDesc<TRef<DecodePcodeExecutionException>,
		Ent<Ent<Bot, TRef<String>>, TLong>> MDESC_JIT_COMPILED_PASSAGE__CREATE_DECODE_ERROR =
			MthDesc.returns(T_DECODE_PCODE_EXECUTION_EXCEPTION)
					.param(T_STRING)
					.param(Types.T_LONG)
					.build();
	public static final MthDesc<TRef<ExitSlot>,
		Ent<Ent<Bot, TLong>, TRef<RegisterValue>>> MDESC_JIT_COMPILED_PASSAGE__CREATE_EXIT_SLOT =
			MthDesc.returns(T_EXIT_SLOT).param(Types.T_LONG).param(T_REGISTER_VALUE).build();
	public static final MthDesc<TRef<PcodeOp>,
		Ent<Ent<Ent<Ent<Ent<Bot, TRef<Address>>, TInt>, TInt>, TRef<Varnode[]>>,
			TRef<Varnode>>> MDESC_JIT_COMPILED_PASSAGE__CREATE_OP =
				MthDesc.derive(JitCompiledPassage::createOp)
						.check(MthDesc::returns, T_PCODE_OP)
						.check(MthDesc::param, T_ADDRESS)
						.check(MthDesc::param, Types.T_INT)
						.check(MthDesc::param, Types.T_INT)
						.check(MthDesc::param, TARR_VARNODE)
						.check(MthDesc::param, T_VARNODE)
						.check(MthDesc::build);
	public static final MthDesc<TRef<Varnode>,
		Ent<Ent<Ent<Ent<Bot, TRef<AddressFactory>>, TRef<String>>, TLong>,
			TInt>> MDESC_JIT_COMPILED_PASSAGE__CREATE_VARNODE =
				MthDesc.returns(T_VARNODE)
						.param(T_ADDRESS_FACTORY)
						.param(T_STRING)
						.param(Types.T_LONG)
						.param(Types.T_INT)
						.build();
	public static final MthDesc<TRef<EntryPoint>,
		Ent<Bot, TRef<ExitSlot>>> MDESC_JIT_COMPILED_PASSAGE__GET_CHAINED =
			MthDesc.returns(T_ENTRY_POINT).param(T_EXIT_SLOT).build();
	public static final MthDesc<TRef<Language>,
		Ent<Bot, TRef<String>>> MDESC_JIT_COMPILED_PASSAGE__GET_LANGUAGE =
			MthDesc.returns(T_LANGUAGE).param(T_STRING).build();
	public static final MthDesc<TRef<PcodeUseropDefinition<byte[]>>,
		Ent<Bot, TRef<String>>> MDESC_JIT_COMPILED_PASSAGE__GET_USEROP_DEFINITION =
			MthDesc.deriveInst(JitCompiledPassage::getUseropDefinition)
					.check(MthDesc::returns, T_PCODE_USEROP_DEFINITION__BYTEARR)
					.check(MthDesc::param, T_STRING)
					.check(MthDesc::build);
	public static final MthDesc<TVoid,
		Ent<Ent<Bot, TRef<PcodeUseropDefinition<byte[]>>>,
			TRef<PcodeOp>>> MDESC_JIT_COMPILED_PASSAGE__INVOKE_USEROP =
				MthDesc.deriveInst(JitCompiledPassage::invokeUserop)
						.check(MthDesc::returns, Types.T_VOID)
						.check(MthDesc::param, T_PCODE_USEROP_DEFINITION__BYTEARR)
						.check(MthDesc::param, T_PCODE_OP)
						.check(MthDesc::build);
	public static final MthDesc<TVoid,
		Ent<Ent<Ent<Bot, TRef<int[]>>, TRef<int[]>>,
			TRef<int[]>>> MDESC_JIT_COMPILED_PASSAGE__MP_INT_BINOP =
				MthDesc.returns(Types.T_VOID)
						.param(Types.T_INT_ARR)
						.param(Types.T_INT_ARR)
						.param(Types.T_INT_ARR)
						.build();
	public static final MthDesc<TInt,
		Ent<Ent<Ent<Bot, TRef<byte[]>>, TInt>, TInt>> MDESC_JIT_COMPILED_PASSAGE__READ_BOOL_N =
			MthDesc.returns(Types.T_BOOL)
					.param(Types.T_BYTE_ARR)
					.param(Types.T_INT)
					.param(Types.T_INT)
					.build();
	public static final MthDesc<TInt,
		Ent<Ent<Bot, TRef<byte[]>>, TInt>> MDESC_JIT_COMPILED_PASSAGE__READ_INTX =
			MthDesc.returns(Types.T_INT).param(Types.T_BYTE_ARR).param(Types.T_INT).build();
	public static final MthDesc<TLong,
		Ent<Ent<Bot, TRef<byte[]>>, TInt>> MDESC_JIT_COMPILED_PASSAGE__READ_LONGX =
			MthDesc.returns(Types.T_LONG).param(Types.T_BYTE_ARR).param(Types.T_INT).build();
	public static final MthDesc<TVoid, Ent<Ent<Bot, TLong>,
		TRef<RegisterValue>>> MDESC_JIT_COMPILED_PASSAGE__SET_$OR_WRITE_COUNTER_AND_CONTEXT =
			MthDesc.returns(Types.T_VOID).param(Types.T_LONG).param(T_REGISTER_VALUE).build();
	public static final MthDesc<TInt, Ent<Ent<Bot, TInt>,
		TInt>> MDESC_JIT_COMPILED_PASSAGE__$FLAGBIT_INT_RAW =
			MthDesc.returns(Types.T_INT).param(Types.T_INT).param(Types.T_INT).build();
	public static final MthDesc<TLong, Ent<Ent<Bot, TLong>,
		TLong>> MDESC_JIT_COMPILED_PASSAGE__$FLAGBIT_LONG_RAW =
			MthDesc.returns(Types.T_LONG).param(Types.T_LONG).param(Types.T_LONG).build();
	public static final MthDesc<TInt,
		Ent<Ent<Ent<Bot, TRef<int[]>>, TRef<int[]>>,
			TInt>> MDESC_JIT_COMPILED_PASSAGE__$FLAGBIT_MP_INT =
				MthDesc.returns(Types.T_INT)
						.param(Types.T_INT_ARR)
						.param(Types.T_INT_ARR)
						.param(Types.T_INT)
						.build();
	public static final MthDesc<TVoid, Bot> MDESC_THROWABLE__PRINT_STACK_TRACE =
		MthDesc.returns(Types.T_VOID).build();

	/**
	 * This is just to assure all the methods referred to below have the same signature. The fields
	 * here should not be used in any code, written, generated, or otherwise.
	 */
	interface WriteIntX {
		WriteIntX AE1 = JitCompiledPassage::writeInt1;
		WriteIntX BE2 = JitCompiledPassage::writeIntBE2;
		WriteIntX BE3 = JitCompiledPassage::writeIntBE3;
		WriteIntX BE4 = JitCompiledPassage::writeIntBE4;

		WriteIntX LE2 = JitCompiledPassage::writeIntLE2;
		WriteIntX LE3 = JitCompiledPassage::writeIntLE3;
		WriteIntX LE4 = JitCompiledPassage::writeIntLE4;

		void writeIntX(int value, byte[] arr, int offset);
	}

	/**
	 * This is just to assure all the methods referred to below have the same signature. The fields
	 * here should not be used in any code, written, generated, or otherwise.
	 */
	interface WriteLongX {
		WriteLongX AE1 = JitCompiledPassage::writeLong1;
		WriteLongX BE2 = JitCompiledPassage::writeLongBE2;
		WriteLongX BE3 = JitCompiledPassage::writeLongBE3;
		WriteLongX BE4 = JitCompiledPassage::writeLongBE4;
		WriteLongX BE5 = JitCompiledPassage::writeLongBE5;
		WriteLongX BE6 = JitCompiledPassage::writeLongBE6;
		WriteLongX BE7 = JitCompiledPassage::writeLongBE7;
		WriteLongX BE8 = JitCompiledPassage::writeLongBE8;

		WriteLongX LE2 = JitCompiledPassage::writeLongLE2;
		WriteLongX LE3 = JitCompiledPassage::writeLongLE3;
		WriteLongX LE4 = JitCompiledPassage::writeLongLE4;
		WriteLongX LE5 = JitCompiledPassage::writeLongLE5;
		WriteLongX LE6 = JitCompiledPassage::writeLongLE6;
		WriteLongX LE7 = JitCompiledPassage::writeLongLE7;
		WriteLongX LE8 = JitCompiledPassage::writeLongLE8;

		void writeLongX(long value, byte[] arr, int offset);
	}

	public static final MthDesc<TVoid,
		Ent<Ent<Ent<Bot, TInt>, TRef<byte[]>>, TInt>> MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX =
			MthDesc.derive(JitCompiledPassage::writeInt1)
					.check(MthDesc::returns, Types.T_VOID)
					.check(MthDesc::param, Types.T_INT)
					.check(MthDesc::param, Types.T_BYTE_ARR)
					.check(MthDesc::param, Types.T_INT)
					.check(MthDesc::build);
	public static final MthDesc<TVoid,
		Ent<Ent<Ent<Bot, TLong>, TRef<byte[]>>, TInt>> MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX =
			MthDesc.derive(JitCompiledPassage::writeLong1)
					.check(MthDesc::returns, Types.T_VOID)
					.check(MthDesc::param, Types.T_LONG)
					.check(MthDesc::param, Types.T_BYTE_ARR)
					.check(MthDesc::param, Types.T_INT)
					.check(MthDesc::build);
	public static final MthDesc<TRef<JitThreadBytesPcodeExecutorState>,
		Bot> MDESC_JIT_PCODE_THREAD__GET_STATE =
			MthDesc.returns(T_JIT_THREAD_BYTES_PCODE_EXECUTOR_STATE).build();
	public static final MthDesc<TRef<AddressFactory>, Bot> MDESC_LANGUAGE__GET_ADDRESS_FACTORY =
		MthDesc.returns(T_ADDRESS_FACTORY).build();
	public static final String MDESC_LANGUAGE__GET_DEFAULT_SPACE =
		Type.getMethodDescriptor(Type.getType(AddressSpace.class));
	public static final MthDesc<TInt, Ent<Bot, TRef<Object>>> MDESC_LIST__ADD =
		MthDesc.returns(Types.T_BOOL).param(T_OBJECT).build();
	public static final MthDesc<TInt, Ent<Bot, TLong>> MDESC_LONG__BIT_COUNT =
		MthDesc.derive(Long::bitCount)
				.check(MthDesc::returns, Types.T_INT)
				.check(MthDesc::param, Types.T_LONG)
				.check(MthDesc::build);
	public static final MthDesc<TInt, Ent<Ent<Bot, TLong>, TLong>> MDESC_LONG__COMPARE =
		MthDesc.returns(Types.T_INT).param(Types.T_LONG).param(Types.T_LONG).build();
	public static final MthDesc<TInt, Ent<Bot, TLong>> MDESC_LONG__NUMBER_OF_LEADING_ZEROS =
		MthDesc.derive(Long::numberOfLeadingZeros)
				.check(MthDesc::returns, Types.T_INT)
				.check(MthDesc::param, Types.T_LONG)
				.check(MthDesc::build);
	public static final MthDesc<TVoid, Ent<Bot, TRef<String>>> MDESC_LOWLEVEL_ERROR__$INIT =
		MthDesc.returns(Types.T_VOID).param(T_STRING).build();
	public static final MthDesc<TVoid, Bot> MDESC_OBJECT__$INIT =
		MthDesc.returns(Types.T_VOID).build();
	public static final MthDesc<TRef<PcodeUseropLibrary<?>>,
		Bot> MDESC_PCODE_USEROP_DEFINITION__GET_DEFINING_LIBRARY =
			MthDesc.returns(T_PCODE_USEROP_LIBRARY).build();
	public static final MthDesc<TVoid, Ent<Bot, TRef<String>>> MDESC_PRINT_STREAM__PRINTLN =
		MthDesc.returns(Types.T_VOID).param(T_STRING).build();
	public static final MthDesc<TVoid, Ent<Bot, TRef<String>>> MDESC_SLEIGH_LINK_EXCEPTION__$INIT =
		MthDesc.returns(Types.T_VOID).param(T_STRING).build();
	public static final MthDesc<TRef<String>, Ent<Bot, TRef<Object[]>>> MDESC_STRING__FORMATTED =
		MthDesc.returns(T_STRING).param(TARR_OBJECT).build();
	public static final MthDesc<TDouble, Ent<Bot, TDouble>> MDESC_$DOUBLE_UNOP =
		MthDesc.returns(Types.T_DOUBLE).param(Types.T_DOUBLE).build();
	public static final MthDesc<TFloat, Ent<Bot, TFloat>> MDESC_$FLOAT_UNOP =
		MthDesc.returns(Types.T_FLOAT).param(Types.T_FLOAT).build();
	public static final MthDesc<TInt, Ent<Ent<Bot, TInt>, TInt>> MDESC_$INT_BINOP =
		MthDesc.returns(Types.T_INT).param(Types.T_INT).param(Types.T_INT).build();
	public static final MthDesc<TLong, Ent<Ent<Bot, TLong>, TLong>> MDESC_$LONG_BINOP =
		MthDesc.returns(Types.T_LONG).param(Types.T_LONG).param(Types.T_LONG).build();

	public static final MthDesc<TVoid,
		Ent<Ent<Ent<Ent<Bot, TRef<int[]>>, TInt>, TRef<int[]>>, TRef<int[]>>> MDESC_$SHIFT_AA =
			MthDesc.<int[], Integer, int[], int[]> derive(JitCompiledPassage::intLeft)
					.check(MthDesc::returns, Types.T_VOID)
					.check(MthDesc::param, Types.T_INT_ARR)
					.check(MthDesc::param, Types.T_INT)
					.check(MthDesc::param, Types.T_INT_ARR)
					.check(MthDesc::param, Types.T_INT_ARR)
					.check(MthDesc::build);
	public static final MthDesc<TVoid,
		Ent<Ent<Ent<Ent<Bot, TRef<int[]>>, TInt>, TRef<int[]>>, TLong>> MDESC_$SHIFT_AJ =
			MthDesc.<int[], Integer, int[], Long> derive(JitCompiledPassage::intLeft)
					.check(MthDesc::returns, Types.T_VOID)
					.check(MthDesc::param, Types.T_INT_ARR)
					.check(MthDesc::param, Types.T_INT)
					.check(MthDesc::param, Types.T_INT_ARR)
					.check(MthDesc::param, Types.T_LONG)
					.check(MthDesc::build);
	public static final MthDesc<TVoid,
		Ent<Ent<Ent<Ent<Bot, TRef<int[]>>, TInt>, TRef<int[]>>, TInt>> MDESC_$SHIFT_AI =
			MthDesc.<int[], Integer, int[], Integer> derive(JitCompiledPassage::intLeft)
					.check(MthDesc::returns, Types.T_VOID)
					.check(MthDesc::param, Types.T_INT_ARR)
					.check(MthDesc::param, Types.T_INT)
					.check(MthDesc::param, Types.T_INT_ARR)
					.check(MthDesc::param, Types.T_INT)
					.check(MthDesc::build);
	public static final MthDesc<TLong, Ent<Ent<Bot, TLong>, TRef<int[]>>> MDESC_$SHIFT_JA =
		MthDesc.<Long, Long, int[]> derive(JitCompiledPassage::intLeft)
				.check(MthDesc::returns, Types.T_LONG)
				.check(MthDesc::param, Types.T_LONG)
				.check(MthDesc::param, Types.T_INT_ARR)
				.check(MthDesc::build);
	public static final MthDesc<TLong, Ent<Ent<Bot, TLong>, TLong>> MDESC_$SHIFT_JJ =
		MthDesc.<Long, Long, Long> derive(JitCompiledPassage::intLeft)
				.check(MthDesc::returns, Types.T_LONG)
				.check(MthDesc::param, Types.T_LONG)
				.check(MthDesc::param, Types.T_LONG)
				.check(MthDesc::build);
	public static final MthDesc<TLong, Ent<Ent<Bot, TLong>, TInt>> MDESC_$SHIFT_JI =
		MthDesc.<Long, Long, Integer> derive(JitCompiledPassage::intLeft)
				.check(MthDesc::returns, Types.T_LONG)
				.check(MthDesc::param, Types.T_LONG)
				.check(MthDesc::param, Types.T_INT)
				.check(MthDesc::build);
	public static final MthDesc<TInt, Ent<Ent<Bot, TInt>, TRef<int[]>>> MDESC_$SHIFT_IA =
		MthDesc.<Integer, Integer, int[]> derive(JitCompiledPassage::intLeft)
				.check(MthDesc::returns, Types.T_INT)
				.check(MthDesc::param, Types.T_INT)
				.check(MthDesc::param, Types.T_INT_ARR)
				.check(MthDesc::build);
	public static final MthDesc<TInt, Ent<Ent<Bot, TInt>, TLong>> MDESC_$SHIFT_IJ =
		MthDesc.<Integer, Integer, Long> derive(JitCompiledPassage::intLeft)
				.check(MthDesc::returns, Types.T_INT)
				.check(MthDesc::param, Types.T_INT)
				.check(MthDesc::param, Types.T_LONG)
				.check(MthDesc::build);
	public static final MthDesc<TInt, Ent<Ent<Bot, TInt>, TInt>> MDESC_$SHIFT_II =
		MthDesc.<Integer, Integer, Integer> derive(JitCompiledPassage::intLeft)
				.check(MthDesc::returns, Types.T_INT)
				.check(MthDesc::param, Types.T_INT)
				.check(MthDesc::param, Types.T_INT)
				.check(MthDesc::build);
}
