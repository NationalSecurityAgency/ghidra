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

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.reflect.TypeLiteral;
import org.objectweb.asm.Type;

import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.emu.jit.*;
import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.ExitSlot;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.Varnode;

/**
 * Various constants (namely class names, type descriptions, method descriptions, etc. used during
 * bytecode generation.
 */
@SuppressWarnings("javadoc")
public interface GenConsts {
	public static final int BLOCK_SIZE = SemisparseByteArray.BLOCK_SIZE;

	public static final String TDESC_ADDRESS = Type.getDescriptor(Address.class);
	public static final String TDESC_ADDRESS_FACTORY = Type.getDescriptor(AddressFactory.class);
	public static final String TDESC_ADDRESS_SPACE = Type.getDescriptor(AddressSpace.class);
	public static final String TDESC_BYTE_ARR = Type.getDescriptor(byte[].class);
	public static final String TDESC_EXIT_SLOT = Type.getDescriptor(ExitSlot.class);
	public static final String TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE =
		Type.getDescriptor(JitBytesPcodeExecutorState.class);
	public static final String TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE =
		Type.getDescriptor(JitBytesPcodeExecutorStateSpace.class);
	public static final String TDESC_JIT_PCODE_THREAD = Type.getDescriptor(JitPcodeThread.class);
	public static final String TDESC_LANGUAGE = Type.getDescriptor(Language.class);
	public static final String TDESC_LIST = Type.getDescriptor(List.class);
	public static final String TDESC_PCODE_USEROP_DEFINITION =
		Type.getDescriptor(PcodeUseropDefinition.class);
	public static final String TDESC_REGISTER_VALUE = Type.getDescriptor(RegisterValue.class);
	public static final String TDESC_STRING = Type.getDescriptor(String.class);
	public static final String TDESC_VARNODE = Type.getDescriptor(Varnode.class);

	public static final String TSIG_LIST_ADDRCTX =
		JitJvmTypeUtils.typeToSignature(new TypeLiteral<List<AddrCtx>>() {}.value);

	public static final String MDESC_ADDR_CTX__$INIT = Type.getMethodDescriptor(Type.VOID_TYPE,
		Type.getType(RegisterValue.class), Type.getType(Address.class));
	public static final String MDESC_ADDRESS_FACTORY__GET_ADDRESS_SPACE =
		Type.getMethodDescriptor(Type.getType(AddressSpace.class), Type.INT_TYPE);
	public static final String MDESC_ADDRESS_SPACE__GET_ADDRESS =
		Type.getMethodDescriptor(Type.getType(Address.class), Type.LONG_TYPE);
	public static final String MDESC_ARRAY_LIST__$INIT = Type.getMethodDescriptor(Type.VOID_TYPE);
	// NOTE: The void (String) form is private....
	public static final String MDESC_ASSERTION_ERROR__$INIT =
		Type.getMethodDescriptor(Type.VOID_TYPE, Type.getType(Object.class));
	public static final String MDESC_DOUBLE__DOUBLE_TO_RAW_LONG_BITS =
		Type.getMethodDescriptor(Type.LONG_TYPE, Type.DOUBLE_TYPE);
	public static final String MDESC_DOUBLE__IS_NAN =
		Type.getMethodDescriptor(Type.BOOLEAN_TYPE, Type.DOUBLE_TYPE);
	public static final String MDESC_DOUBLE__LONG_BITS_TO_DOUBLE =
		Type.getMethodDescriptor(Type.DOUBLE_TYPE, Type.LONG_TYPE);
	public static final String MDESC_FLOAT__FLOAT_TO_RAW_INT_BITS =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.FLOAT_TYPE);
	public static final String MDESC_FLOAT__INT_BITS_TO_FLOAT =
		Type.getMethodDescriptor(Type.FLOAT_TYPE, Type.INT_TYPE);
	public static final String MDESC_FLOAT__IS_NAN =
		Type.getMethodDescriptor(Type.BOOLEAN_TYPE, Type.FLOAT_TYPE);
	public static final String MDESC_ILLEGAL_ARGUMENT_EXCEPTION__$INIT =
		Type.getMethodDescriptor(Type.VOID_TYPE, Type.getType(String.class));
	public static final String MDESC_INTEGER__BIT_COUNT =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.INT_TYPE);
	public static final String MDESC_INTEGER__COMPARE_UNSIGNED =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.INT_TYPE, Type.INT_TYPE);
	public static final String MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.INT_TYPE);
	public static final String MDESC_INTEGER__TO_UNSIGNED_LONG =
		Type.getMethodDescriptor(Type.LONG_TYPE, Type.INT_TYPE);
	public static final String MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE__GET_LANGUAGE =
		Type.getMethodDescriptor(Type.getType(Language.class));
	public static final String MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE__GET_SPACE_FOR =
		Type.getMethodDescriptor(Type.getType(JitBytesPcodeExecutorStateSpace.class),
			Type.getType(AddressSpace.class));
	public static final String MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__GET_DIRECT =
		Type.getMethodDescriptor(Type.getType(byte[].class), Type.LONG_TYPE);
	public static final String MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__READ =
		Type.getMethodDescriptor(Type.getType(byte[].class), Type.LONG_TYPE, Type.INT_TYPE);
	public static final String MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__WRITE =
		Type.getMethodDescriptor(Type.VOID_TYPE, Type.LONG_TYPE, Type.getType(byte[].class),
			Type.INT_TYPE, Type.INT_TYPE);
	public static final String MDESC_JIT_COMPILED_PASSAGE__CONV_OFFSET2_TO_LONG =
		Type.getMethodDescriptor(Type.LONG_TYPE, Type.INT_TYPE, Type.INT_TYPE);
	public static final String MDESC_JIT_COMPILED_PASSAGE__COUNT =
		Type.getMethodDescriptor(Type.VOID_TYPE, Type.INT_TYPE, Type.INT_TYPE);
	public static final String MDESC_JIT_COMPILED_PASSAGE__CREATE_CONTEXT =
		Type.getMethodDescriptor(Type.getType(RegisterValue.class), Type.getType(Language.class),
			Type.getType(String.class));
	public static final String MDESC_JIT_COMPILED_PASSAGE__CREATE_DECODE_ERROR =
		Type.getMethodDescriptor(Type.getType(DecodePcodeExecutionException.class),
			Type.getType(String.class), Type.LONG_TYPE);
	public static final String MDESC_JIT_COMPILED_PASSAGE__CREATE_EXIT_SLOT =
		Type.getMethodDescriptor(Type.getType(ExitSlot.class), Type.LONG_TYPE,
			Type.getType(RegisterValue.class));
	public static final String MDESC_JIT_COMPILED_PASSAGE__CREATE_VARNODE =
		Type.getMethodDescriptor(Type.getType(Varnode.class), Type.getType(AddressFactory.class),
			Type.getType(String.class), Type.LONG_TYPE, Type.INT_TYPE);
	public static final String MDESC_JIT_COMPILED_PASSAGE__GET_CHAINED =
		Type.getMethodDescriptor(Type.getType(EntryPoint.class), Type.getType(ExitSlot.class));
	public static final String MDESC_JIT_COMPILED_PASSAGE__GET_LANGUAGE =
		Type.getMethodDescriptor(Type.getType(Language.class), Type.getType(String.class));
	public static final String MDESC_JIT_COMPILED_PASSAGE__GET_USEROP_DEFINITION =
		Type.getMethodDescriptor(Type.getType(PcodeUseropDefinition.class),
			Type.getType(String.class));
	public static final String MDESC_JIT_COMPILED_PASSAGE__INVOKE_USEROP =
		Type.getMethodDescriptor(Type.VOID_TYPE, Type.getType(PcodeUseropDefinition.class),
			Type.getType(Varnode.class), Type.getType(Varnode[].class));
	public static final String MDESC_JIT_COMPILED_PASSAGE__READ_INTX =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.getType(byte[].class), Type.INT_TYPE);
	public static final String MDESC_JIT_COMPILED_PASSAGE__READ_LONGX =
		Type.getMethodDescriptor(Type.LONG_TYPE, Type.getType(byte[].class), Type.INT_TYPE);
	public static final String MDESC_JIT_COMPILED_PASSAGE__RETIRE_COUNTER_AND_CONTEXT =
		Type.getMethodDescriptor(Type.VOID_TYPE, Type.LONG_TYPE, Type.getType(RegisterValue.class));
	public static final String MDESC_JIT_COMPILED_PASSAGE__S_CARRY_INT_RAW =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.INT_TYPE, Type.INT_TYPE);
	public static final String MDESC_JIT_COMPILED_PASSAGE__S_CARRY_LONG_RAW =
		Type.getMethodDescriptor(Type.LONG_TYPE, Type.LONG_TYPE, Type.LONG_TYPE);
	public static final String MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX =
		Type.getMethodDescriptor(Type.VOID_TYPE, Type.INT_TYPE, Type.getType(byte[].class),
			Type.INT_TYPE);
	public static final String MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX =
		Type.getMethodDescriptor(Type.VOID_TYPE, Type.LONG_TYPE, Type.getType(byte[].class),
			Type.INT_TYPE);
	public static final String MDESC_JIT_PCODE_THREAD__GET_STATE =
		Type.getMethodDescriptor(Type.getType(JitThreadBytesPcodeExecutorState.class));
	public static final String MDESC_LANGUAGE__GET_ADDRESS_FACTORY =
		Type.getMethodDescriptor(Type.getType(AddressFactory.class));
	public static final String MDESC_LANGUAGE__GET_DEFAULT_SPACE =
		Type.getMethodDescriptor(Type.getType(AddressSpace.class));
	public static final String MDESC_LIST__ADD =
		Type.getMethodDescriptor(Type.BOOLEAN_TYPE, Type.getType(Object.class));
	public static final String MDESC_LONG__BIT_COUNT =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.LONG_TYPE);
	public static final String MDESC_LONG__COMPARE_UNSIGNED =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.LONG_TYPE, Type.LONG_TYPE);
	public static final String MDESC_LONG__NUMBER_OF_LEADING_ZEROS =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.LONG_TYPE);
	public static final String MDESC_LOW_LEVEL_ERROR__$INIT =
		Type.getMethodDescriptor(Type.VOID_TYPE, Type.getType(String.class));
	public static final String MDESC_PCODE_USEROP_DEFINITION__GET_DEFINING_LIBRARY =
		Type.getMethodDescriptor(Type.getType(PcodeUseropLibrary.class));
	public static final String MDESC_SLEIGH_LINK_EXCEPTION__$INIT =
		Type.getMethodDescriptor(Type.VOID_TYPE, Type.getType(String.class));

	public static final String MDESC_$DOUBLE_UNOP =
		Type.getMethodDescriptor(Type.DOUBLE_TYPE, Type.DOUBLE_TYPE);
	public static final String MDESC_$FLOAT_UNOP =
		Type.getMethodDescriptor(Type.FLOAT_TYPE, Type.FLOAT_TYPE);
	public static final String MDESC_$INT_BINOP =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.INT_TYPE, Type.INT_TYPE);
	public static final String MDESC_$LONG_BINOP =
		Type.getMethodDescriptor(Type.LONG_TYPE, Type.LONG_TYPE, Type.LONG_TYPE);
	public static final String MDESC_$SHIFT_JJ =
		Type.getMethodDescriptor(Type.LONG_TYPE, Type.LONG_TYPE, Type.LONG_TYPE);
	public static final String MDESC_$SHIFT_JI =
		Type.getMethodDescriptor(Type.LONG_TYPE, Type.LONG_TYPE, Type.INT_TYPE);
	public static final String MDESC_$SHIFT_IJ =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.INT_TYPE, Type.LONG_TYPE);
	public static final String MDESC_$SHIFT_II =
		Type.getMethodDescriptor(Type.INT_TYPE, Type.INT_TYPE, Type.INT_TYPE);

	public static final String NAME_ADDR_CTX = Type.getInternalName(AddrCtx.class);
	public static final String NAME_ADDRESS = Type.getInternalName(Address.class);
	public static final String NAME_ADDRESS_FACTORY = Type.getInternalName(AddressFactory.class);
	public static final String NAME_ADDRESS_SPACE = Type.getInternalName(AddressSpace.class);
	public static final String NAME_ARRAY_LIST = Type.getInternalName(ArrayList.class);
	public static final String NAME_ASSERTION_ERROR = Type.getInternalName(AssertionError.class);
	public static final String NAME_DOUBLE = Type.getInternalName(Double.class);
	public static final String NAME_EXIT_SLOT = Type.getInternalName(ExitSlot.class);
	public static final String NAME_FLOAT = Type.getInternalName(Float.class);
	public static final String NAME_ILLEGAL_ARGUMENT_EXCEPTION =
		Type.getInternalName(IllegalArgumentException.class);
	public static final String NAME_INTEGER = Type.getInternalName(Integer.class);
	public static final String NAME_JIT_BYTES_PCODE_EXECUTOR_STATE =
		Type.getInternalName(JitBytesPcodeExecutorState.class);
	public static final String NAME_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE =
		Type.getInternalName(JitBytesPcodeExecutorStateSpace.class);
	public static final String NAME_JIT_COMPILED_PASSAGE =
		Type.getInternalName(JitCompiledPassage.class);
	public static final String NAME_JIT_PCODE_THREAD = Type.getInternalName(JitPcodeThread.class);
	public static final String NAME_LANGUAGE = Type.getInternalName(Language.class);
	public static final String NAME_LIST = Type.getInternalName(List.class);
	public static final String NAME_LONG = Type.getInternalName(Long.class);
	public static final String NAME_LOW_LEVEL_ERROR = Type.getInternalName(LowlevelError.class);
	public static final String NAME_MATH = Type.getInternalName(Math.class);
	public static final String NAME_OBJECT = Type.getInternalName(Object.class);
	public static final String NAME_PCODE_USEROP_DEFINITION =
		Type.getInternalName(PcodeUseropDefinition.class);
	public static final String NAME_SLEIGH_LINK_EXCEPTION =
		Type.getInternalName(SleighLinkException.class);
	public static final String NAME_THROWABLE = Type.getInternalName(Throwable.class);
	public static final String NAME_VARNODE = Type.getInternalName(Varnode.class);
}
