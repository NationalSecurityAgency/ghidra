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

import static ghidra.pcode.emu.jit.analysis.JitVarScopeModel.*;
import static org.objectweb.asm.Opcodes.*;

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.collections4.iterators.ReverseListIterator;
import org.objectweb.asm.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.JitCompiler;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.GenConsts;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.var.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Varnode;

/**
 * Type variable allocation phase for JIT-accelerated emulation.
 * 
 * <p>
 * The implements the Variable Allocation phase of the {@link JitCompiler} using a very simple
 * placement and another "voting" algorithm to decide the allocated JVM variable types. We place/map
 * variables by their storage varnodes, coalescing them as needed. Coalescing is performed for
 * overlapping, but not abutting varnodes. This allocation is anticipated by the
 * {@link JitVarScopeModel}, which performs the actual coalescing. Because multiple SSA variables
 * will almost certainly occupy the same varnode, we employ another voting system. For example, the
 * register {@code RAX} may be re-used many times within a passage. In some cases, it might be used
 * to return a floating-point value. In others (and <em>probably</em> more commonly) it will be used
 * to return an integral value. The more common case in the passage determines the JVM type of the
 * local variable allocated for {@code RAX}. Note that variables which occupy only part of a
 * coalesced varnode always vote for a JVM {@code int}, because of the shifting and masking required
 * to extract that part.
 * 
 * <p>
 * The allocation process is very simple, presuming successful type assignment:
 * 
 * <ol>
 * <li>Vote Tabulation</li>
 * <li>Index Reservation</li>
 * <li>Handler Creation</li>
 * </ol>
 * 
 * <h2>Vote Tabulation</h2>
 * <p>
 * Every SSA variable (excluding constants and memory variables) contributes a vote for the type of
 * its allocated local. If the varnode matches exactly, the vote is for the JVM type of the
 * variable's assigned p-code type. The type mapping is simple: For integral types, we allocate
 * using the smaller JVM type that fits the p-code type. For floating-point types, we allocate using
 * the JVM type that exactly matches the p-code type. If the varnode is larger, i.e., because it's
 * the result of coalescing, then the vote is for the smaller JVM integer type that fits the full
 * varnode. Consider the following p-code:
 * 
 * <pre>
 * 1. RAX = FLOAT_ADD RCX, RDX
 * 2. EAX = FLOAT_ADD EBX, 0x3f800000:4 # 1.0f
 * </pre>
 * 
 * <p>
 * Several values and variables are at play here. We tabulate the type assignments and resulting
 * votes:
 * 
 * <table border="1">
 * <tr>
 * <th>SSA Var</th>
 * <th>Type</th>
 * <th>Varnode</th>
 * <th>Vote</th>
 * </tr>
 * <tr>
 * <td>{@code RCX}<sub>in</sub></td>
 * <td>{@link DoubleJitType#F8 float8}</td>
 * <td>{@code RCX}</td>
 * <td>{@code double}</td>
 * </tr>
 * <tr>
 * <td>{@code RDX}<sub>in</sub></td>
 * <td>{@link DoubleJitType#F8 float8}</td>
 * <td>{@code RDX}</td>
 * <td>{@code double}</td>
 * </tr>
 * <tr>
 * <td>{@code RAX}<sub>1</sub></td>
 * <td>{@link DoubleJitType#F8 float8}</td>
 * <td>{@code RAX}</td>
 * <td>{@code double}</td>
 * </tr>
 * <tr>
 * <td>{@code EBX}<sub>in</sub></td>
 * <td>{@link FloatJitType#F4 float4}</td>
 * <td>{@code EBX}</td>
 * <td>{@code float}</td>
 * </tr>
 * <tr>
 * <td>{@code 0x3f800000:4}</td>
 * <td>{@link FloatJitType#F4 float4}</td>
 * </tr>
 * <tr>
 * <td>{@code EAX}<sub>2</sub></td>
 * <td>{@link FloatJitType#F4 float4}</td>
 * <td>{@code RAX}</td>
 * <td>{@code long}</td>
 * </tr>
 * </table>
 * 
 * The registers {@code RCX}, {@code RDX}, and {@code EBX} are trivially allocated as locals of JVM
 * types {@code double}, {@code double}, and {@code float}, respectively. It is also worth noting
 * that {@code 0x3f800000} is allocated as a {@code float} constant in the classfile's constant
 * pool. Now, we consider {@code RAX}. The varnodes for {@code RAX}<sub>1</sub> and
 * {@code EAX}<sub>2</sub> are coalesced to {@code RAX}. {@code RAX}<sub>1</sub> casts its vote for
 * {@code double}; whereas, {@code EAX}<sub>2</sub> casts its vote for {@code long}. This is because
 * placing {@code EAX}<sub>2</sub>'s value into the larger varnode requires bitwise operators, which
 * on the JVM, require integer operands. Thus the votes result in a tie, and favoring integral
 * types, we allocate {@code RAX} in a JVM {@code long}.
 * 
 * <h2>Index Reservation</h2>
 * <p>
 * After all the votes have been tabulated, we go through the results in address order, reserving
 * JVM local indices and assigning types. Note that we must reserve two indices for every variable
 * of type {@code long} or {@code double}, as specific by the JVM. Each of these reservations is
 * tracked in a {@link JvmLocal}. Note that index 0 is already reserved by the JVM for the
 * {@code this} ref, so we start our counting at 1. Also, some portions of the code generator may
 * need to allocate additional temporary locals, so we must allow access to the next free index
 * after all reservations are complete.
 * 
 * <h2>Handler Creation</h2>
 * <p>
 * This actually extends a little beyond allocation, but this is a suitable place for it: All SSA
 * values are assigned a handler, including constants and memory variables. Variables which access
 * the same varnode get the same handler. For varnodes that are allocated in a JVM local, we create
 * a handler that generates loads and stores to that local, e.g., {@link Opcodes#ILOAD iload}. For
 * constant varnodes, we create a handler that generates {@link Opcodes#LDC ldc} instructions. For
 * memory varnodes, we create a handler that generates a sequence of method invocations on the
 * {@link JitBytesPcodeExecutorState state}. The code generator will delegate to these handlers in
 * order to generate reads and writes of the corresponding variables, as well as to prepare any
 * resources to facilitate access, e.g., pre-fetching items from the
 * {@link JitBytesPcodeExecutorState state} in the generated constructor.
 * 
 * @implNote There are many artifacts below that anticipate supporting p-code types greater than 8
 *           bytes in size. One method to support that is to allocate multiple JVM locals per p-code
 *           varnode. Consider a 16-byte (128-bit) integer. We could allocate 4 JVM {@code int}
 *           locals and then emit bytecode that performs the gradeschool-style arithmetic. I suspect
 *           this would perform better than just using refs to {@link BigInteger}, because it avoids
 *           heap pollution, and also may avoid some unnecessary arithmetic, esp., for the more
 *           significant portions that get dropped.
 * @implNote <b>TODO</b>: It would be nice to detect varnode re-use under a different type and
 *           generate the appropriate declarations and handlers. This doesn't seem terribly complex,
 *           and it stands to spare us some casts. What's not clear is whether this offers any real
 *           run-time benefit.
 */
public class JitAllocationModel {

	/**
	 * An allocated JVM local
	 * 
	 * @param index the index reserved for this local
	 * @param name the human-readable name for this local
	 * @param type a type for this local
	 * @param vn the varnode whose value this local holds
	 */
	public record JvmLocal(int index, String name, SimpleJitType type, Varnode vn) {

		/**
		 * Emit bytecode into the class constructor.
		 * 
		 * @param gen the code generator
		 * @param iv the visitor for the class constructor
		 */
		public void generateInitCode(JitCodeGenerator gen, MethodVisitor iv) {
			VarGen.generateValInitCode(gen, vn);
		}

		/**
		 * Emit bytecode at the top of the {@link JitCompiledPassage#run(int) run} method.
		 * 
		 * <p>
		 * This will declare all of the allocated locals for the entirety of the method.
		 * 
		 * @param gen the code generator
		 * @param start a label at the top of the method
		 * @param end a label at the end of the method
		 * @param rv the visitor for the run method
		 */
		public void generateDeclCode(JitCodeGenerator gen, Label start, Label end,
				MethodVisitor rv) {
			rv.visitLocalVariable(name, Type.getDescriptor(type.javaType()), null, start, end,
				index);
		}

		/**
		 * Emit bytecode to load the varnode's value onto the JVM stack.
		 * 
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		public void generateLoadCode(MethodVisitor rv) {
			rv.visitVarInsn(type.opcodeLoad(), index);
		}

		/**
		 * Emit bytecode to store the value on the JVM stack into the varnode.
		 * 
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		public void generateStoreCode(MethodVisitor rv) {
			rv.visitVarInsn(type.opcodeStore(), index);
		}

		/**
		 * Emit bytecode to bring this varnode into scope.
		 * 
		 * <p>
		 * This will copy the value from the {@link JitBytesPcodeExecutorState state} into the local
		 * variable.
		 * 
		 * @param gen the code generator
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		public void generateBirthCode(JitCodeGenerator gen, MethodVisitor rv) {
			VarGen.generateValReadCodeDirect(gen, type, vn, rv);
			generateStoreCode(rv);
		}

		/**
		 * Emit bytecode to take this varnode out of scope.
		 * 
		 * <p>
		 * This will copy the value from the local variable into the
		 * {@link JitBytesPcodeExecutorState state}.
		 * 
		 * @param gen the code generator
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int)} method
		 */
		public void generateRetireCode(JitCodeGenerator gen, MethodVisitor rv) {
			generateLoadCode(rv);
			VarGen.generateValWriteCodeDirect(gen, type, vn, rv);
		}
	}

	/**
	 * A handler that knows how to load and store variable values onto and from the JVM stack.
	 */
	public interface VarHandler {
		/**
		 * Get the p-code type of the variable this handler handles.
		 * 
		 * @return the type
		 */
		JitType type();

		/**
		 * Emit bytecode into the class constructor.
		 * 
		 * @param gen the code generator
		 * @param iv the visitor for the class constructor
		 */
		void generateInitCode(JitCodeGenerator gen, MethodVisitor iv);

		/**
		 * If needed, emit bytecode at the top of the {@link JitCompiledPassage#run(int) run}
		 * method.
		 * 
		 * @param gen the code generator
		 * @param start a label at the top of the method
		 * @param end a label at the end of the method
		 * @param rv the visitor for the run method
		 */
		void generateDeclCode(JitCodeGenerator gen, Label start, Label end, MethodVisitor rv);

		/**
		 * Emit bytecode to load the varnode's value onto the JVM stack.
		 * 
		 * @param gen the code generator
		 * @param type the p-code type of the value expected on the JVM stack by the proceeding
		 *            bytecode
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		void generateLoadCode(JitCodeGenerator gen, JitType type, MethodVisitor rv);

		/**
		 * Emit bytecode to load the varnode's value onto the JVM stack.
		 * 
		 * @param gen the code generator
		 * @param type the p-code type of the value produced on the JVM stack by the preceding
		 *            bytecode
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		void generateStoreCode(JitCodeGenerator gen, JitType type, MethodVisitor rv);
	}

	/**
	 * A handler for p-code variables composed of a single JVM local variable.
	 */
	public interface OneLocalVarHandler extends VarHandler {
		/**
		 * Get the local variable into which this p-code variable is allocated
		 * 
		 * @return the local
		 */
		JvmLocal local();

		@Override
		default void generateInitCode(JitCodeGenerator gen, MethodVisitor iv) {
			// Generator inits decls directly
		}

		@Override
		default void generateDeclCode(JitCodeGenerator gen, Label start, Label end,
				MethodVisitor rv) {
			// Generator calls decls directly
		}

		@Override
		default void generateLoadCode(JitCodeGenerator gen, JitType type, MethodVisitor rv) {
			local().generateLoadCode(rv);
			TypeConversions.generate(gen, this.type(), type, rv);
		}

		@Override
		default void generateStoreCode(JitCodeGenerator gen, JitType type, MethodVisitor rv) {
			TypeConversions.generate(gen, type, this.type(), rv);
			local().generateStoreCode(rv);
		}
	}

	/**
	 * The handler for a p-code variable allocated in one JVM {@code int}.
	 * 
	 * @param local the JVM local
	 * @param type the p-code type
	 */
	public record IntVarAlloc(JvmLocal local, IntJitType type) implements OneLocalVarHandler {}

	/**
	 * The handler for a p-code variable allocated in one JVM {@code long}.
	 * 
	 * @param local the JVM local
	 * @param type the p-code type
	 */
	public record LongVarAlloc(JvmLocal local, LongJitType type) implements OneLocalVarHandler {}

	/**
	 * The handler for a p-code variable allocated in one JVM {@code float}.
	 * 
	 * @param local the JVM local
	 * @param type the p-code type
	 */
	public record FloatVarAlloc(JvmLocal local, FloatJitType type) implements OneLocalVarHandler {}

	/**
	 * The handler for a p-code variable allocated in one JVM {@code double}.
	 * 
	 * @param local the JVM local
	 * @param type the p-code type
	 */
	public record DoubleVarAlloc(JvmLocal local, DoubleJitType type)
			implements OneLocalVarHandler {}

	/**
	 * A portion of a multi-local variable handler.
	 * 
	 * <p>
	 * This portion is allocated in a JVM local. When loading with a positive shift, the value is
	 * shifted to the right to place it into position.
	 * 
	 * @param local the local variable allocated to this part
	 * @param shift the number of bytes and direction to shift
	 */
	public record MultiLocalPart(JvmLocal local, int shift) {
		private JitType chooseLargerType(JitType t1, JitType t2) {
			return t1.size() > t2.size() ? t1 : t2;
		}

		/**
		 * Emit bytecode to load the value from this local and position it in a value on the JVM
		 * stack.
		 * 
		 * <p>
		 * If multiple parts are to be combined, the caller should emit a bitwise or after all loads
		 * but the first.
		 * 
		 * @param gen the code generator
		 * @param type the p-code type of the value expected on the stack by the proceeding
		 *            bytecode, which may be to load additional parts
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 * 
		 * @implNote We must keep temporary values in a variable of the larger of the local's or the
		 *           expected type, otherwise bits may get dropped while positioning the value.
		 */
		public void generateLoadCode(JitCodeGenerator gen, JitType type, MethodVisitor rv) {
			local.generateLoadCode(rv);
			JitType tempType = chooseLargerType(local.type, type);
			TypeConversions.generate(gen, local.type, tempType, rv);
			if (shift > 0) {
				switch (tempType) {
					case IntJitType t -> {
						rv.visitLdcInsn(shift * Byte.SIZE);
						rv.visitInsn(IUSHR);
					}
					case LongJitType t -> {
						rv.visitLdcInsn(shift * Byte.SIZE);
						rv.visitInsn(LUSHR);
					}
					default -> throw new AssertionError();
				}
			}
			else if (shift < 0) {
				switch (tempType) {
					case IntJitType t -> {
						rv.visitLdcInsn(-shift * Byte.SIZE);
						rv.visitInsn(ISHL);
					}
					case LongJitType t -> {
						rv.visitLdcInsn(-shift * Byte.SIZE);
						rv.visitInsn(LSHL);
					}
					default -> throw new AssertionError();
				}
			}
			TypeConversions.generate(gen, tempType, type, rv);
		}

		/**
		 * Emit bytecode to extract this part from the value on the JVM stack and store it in the
		 * local variable.
		 * 
		 * <p>
		 * If multiple parts are to be stored, the caller should emit a {@link Opcodes#DUP dup} or
		 * {@link Opcodes#DUP2 dup2} before all stores but the last.
		 * 
		 * @param gen the code generator
		 * @param type the p-code type of the value expected on the stack by the proceeding
		 *            bytecode, which may be to load additional parts
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 * 
		 * @implNote We must keep temporary values in a variable of the larger of the local's or the
		 *           expected type, otherwise bits may get dropped while positioning the value.
		 */
		public void generateStoreCode(JitCodeGenerator gen, JitType type, MethodVisitor rv) {
			JitType tempType = chooseLargerType(local.type, type);
			TypeConversions.generate(gen, type, tempType, rv);
			switch (tempType) {
				case IntJitType t -> {
					if (shift > 0) {
						rv.visitLdcInsn(shift * Byte.SIZE);
						rv.visitInsn(ISHL);
					}
					else if (shift < 0) {
						rv.visitLdcInsn(-shift * Byte.SIZE);
						rv.visitInsn(IUSHR);
					}
				}
				case LongJitType t -> {
					if (shift > 0) {
						rv.visitLdcInsn(shift * Byte.SIZE);
						rv.visitInsn(LSHL);
					}
					else if (shift < 0) {
						rv.visitLdcInsn(-shift * Byte.SIZE);
						rv.visitInsn(LUSHR);
					}
				}
				default -> throw new AssertionError();
			}
			TypeConversions.generate(gen, tempType, local.type, rv);
			switch (local.type) {
				case IntJitType t -> {
					int mask = -1 >>> (Integer.SIZE - Byte.SIZE * type.size());
					if (shift > 0) {
						mask <<= shift * Byte.SIZE;
					}
					else {
						mask >>>= -shift * Byte.SIZE;
					}
					rv.visitLdcInsn(mask);
					rv.visitInsn(IAND);
					local.generateLoadCode(rv);
					rv.visitLdcInsn(~mask);
					rv.visitInsn(IAND);
					rv.visitInsn(IOR);
					local.generateStoreCode(rv);
				}
				case LongJitType t -> {
					long mask = -1L >>> (Long.SIZE - Byte.SIZE * type.size());
					if (shift > 0) {
						mask <<= shift * Byte.SIZE;
					}
					else {
						mask >>>= -shift * Byte.SIZE;
					}
					rv.visitLdcInsn(mask);
					rv.visitInsn(LAND);
					local.generateLoadCode(rv);
					rv.visitLdcInsn(~mask);
					rv.visitInsn(LAND);
					rv.visitInsn(LOR);
					local.generateStoreCode(rv);
				}
				default -> throw new AssertionError();
			}
		}
	}

	/**
	 * The handler for a variable allocated in a composition of locals
	 *
	 * <p>
	 * This can also handle a varnode that is a subpiece of a local variable allocated for a larger
	 * varnode. For example, this may handle {@code EAX}, when we have allocated a {@code long} to
	 * hold all of {@code RAX}.
	 * 
	 * @param parts the parts describing how the locals are composed
	 * @param type the p-code type of the (whole) variable
	 */
	public record MultiLocalVarHandler(List<MultiLocalPart> parts, JitType type)
			implements VarHandler {
		@Override
		public void generateInitCode(JitCodeGenerator gen, MethodVisitor iv) {
			// Generator calls local inits directly
		}

		@Override
		public void generateDeclCode(JitCodeGenerator gen, Label start, Label end,
				MethodVisitor rv) {
			// Generator calls local decls directly
		}

		@Override
		public void generateLoadCode(JitCodeGenerator gen, JitType type, MethodVisitor rv) {
			parts.get(0).generateLoadCode(gen, this.type, rv);
			for (MultiLocalPart part : parts.subList(1, parts.size())) {
				part.generateLoadCode(gen, this.type, rv);
				switch (this.type) {
					case IntJitType t -> rv.visitInsn(IOR);
					case LongJitType t -> rv.visitInsn(LOR);
					default -> throw new AssertionError();
				}
			}
			TypeConversions.generate(gen, this.type, type, rv);
		}

		@Override
		public void generateStoreCode(JitCodeGenerator gen, JitType type, MethodVisitor rv) {
			TypeConversions.generate(gen, type, this.type, rv);
			for (MultiLocalPart part : parts.subList(1, parts.size()).reversed()) {
				switch (this.type) {
					case IntJitType t -> rv.visitInsn(DUP);
					case LongJitType t -> rv.visitInsn(DUP2);
					default -> throw new AssertionError();
				}
				part.generateStoreCode(gen, this.type, rv);
			}
			parts.get(0).generateStoreCode(gen, this.type, rv);
		}
	}

	/**
	 * A dummy handler for values/variables that are not allocated in JVM locals
	 */
	public enum NoHandler implements VarHandler {
		/** Singleton */
		INSTANCE;

		@Override
		public JitType type() {
			return null;
		}

		@Override
		public void generateInitCode(JitCodeGenerator gen, MethodVisitor iv) {
		}

		@Override
		public void generateDeclCode(JitCodeGenerator gen, Label start, Label end,
				MethodVisitor rv) {
		}

		@Override
		public void generateLoadCode(JitCodeGenerator gen, JitType type, MethodVisitor rv) {
			throw new AssertionError();
		}

		@Override
		public void generateStoreCode(JitCodeGenerator gen, JitType type, MethodVisitor rv) {
			throw new AssertionError();
		}
	}

	/**
	 * The descriptor of a p-code variable
	 * 
	 * <p>
	 * This is just a logical grouping of a varnode and its assigned p-code type.
	 */
	private record VarDesc(int spaceId, long offset, int size, JitType type, Language language) {
		/**
		 * Create a descriptor from the given varnode and type
		 * 
		 * @param vn the varnode
		 * @param type the p-code type
		 * @param langauge the language
		 * @return the descriptor
		 */
		static VarDesc fromVarnode(Varnode vn, JitType type, Language language) {
			return new VarDesc(vn.getSpace(), vn.getOffset(), vn.getSize(), type, language);
		}

		/**
		 * Derive a name for this variable, to use in the name of allocated local(s)
		 * 
		 * @return the name
		 */
		public String name() {
			AddressFactory factory = language.getAddressFactory();
			AddressSpace space = factory.getAddressSpace(spaceId);
			Register reg = language.getRegister(space, offset, size);
			if (reg != null) {
				return "%s_%d_%s".formatted(reg.getName(), size, type.nm());
			}
			return "s%d_%x_%d_%s".formatted(spaceId, offset, size, type.nm());
		}

		/**
		 * Convert this descriptor back to a varnode
		 * 
		 * @return the varnode
		 */
		public Varnode toVarnode() {
			AddressFactory factory = language.getAddressFactory();
			return new Varnode(factory.getAddressSpace(spaceId).getAddress(offset), size);
		}
	}

	/**
	 * A local that is always allocated in its respective method
	 */
	public interface FixedLocal {
		/**
		 * The JVM index of the local
		 * 
		 * @return the index
		 */
		int index();

		/**
		 * The name of the local
		 * 
		 * @return the name
		 */
		String varName();

		/**
		 * A JVM type descriptor for the local
		 * 
		 * @param nameThis the name of this class, in case it's the this pointer.
		 * @return the type descriptor
		 */
		String typeDesc(String nameThis);

		/**
		 * The JVM opcode used to load the variable
		 * 
		 * @return the load opcode
		 */
		int opcodeLoad();

		/**
		 * The JVM opcode used to store the variable
		 * 
		 * @return the store opcode
		 */
		int opcodeStore();

		/**
		 * Generate the declaration of this variable.
		 * 
		 * <p>
		 * This is not required, but is nice to have when debugging generated code.
		 * 
		 * @param mv the method visitor
		 * @param nameThis the name of the class defining the containing method
		 * @param startLocals the start label which should be placed at the top of the method
		 * @param endLocals the end label which should be placed at the bottom of the method
		 */
		default void generateDeclCode(MethodVisitor mv, String nameThis, Label startLocals,
				Label endLocals) {
			mv.visitLocalVariable(varName(), typeDesc(nameThis), null, startLocals, endLocals,
				index());
		}

		/**
		 * Generate a load of this variable onto the JVM stack.
		 * 
		 * @param mv the method visitor
		 */
		default void generateLoadCode(MethodVisitor mv) {
			mv.visitVarInsn(opcodeLoad(), index());
		}

		/**
		 * Generate a store to this variable from the JVM stack.
		 * 
		 * @param mv the method visitor
		 */
		default void generateStoreCode(MethodVisitor mv) {
			mv.visitVarInsn(opcodeStore(), index());
		}
	}

	/**
	 * Locals that exist in every compiled passage's constructor.
	 */
	public enum InitFixedLocal implements FixedLocal {
		/**
		 * Because we're compiling a non-static method, the JVM reserves index 0 for {@code this}.
		 */
		THIS("this", ALOAD, ASTORE) {
			@Override
			public String typeDesc(String nameThis) {
				return "L" + nameThis + ";";
			}
		},
		/**
		 * The parameter {@code thread} is reserved by the JVM into index 1.
		 */
		THREAD("thread", ALOAD, ASTORE) {
			@Override
			public String typeDesc(String nameThis) {
				return GenConsts.TDESC_JIT_PCODE_THREAD;
			}
		};

		private final String varName;
		private final int opcodeLoad;
		private final int opcodeStore;

		private InitFixedLocal(String varName, int opcodeLoad, int opcodeStore) {
			this.varName = varName;
			this.opcodeLoad = opcodeLoad;
			this.opcodeStore = opcodeStore;
		}

		@Override
		public int index() {
			return ordinal();
		}

		@Override
		public String varName() {
			return varName;
		}

		@Override
		public int opcodeLoad() {
			return opcodeLoad;
		}

		@Override
		public int opcodeStore() {
			return opcodeStore;
		}
	}

	/**
	 * Locals that exist in every compiled passage's {@link JitCompiledPassage#run(int) run} method.
	 */
	public enum RunFixedLocal implements FixedLocal {
		/**
		 * Because we're compiling a non-static method, the JVM reserves index 0 for {@code this}.
		 */
		THIS("this", ALOAD, ASTORE) {
			@Override
			public String typeDesc(String nameThis) {
				return "L" + nameThis + ";";
			}
		},
		/**
		 * The parameter {@code blockId} is reserved by the JVM into index 1.
		 */
		BLOCK_ID("blockId", ILOAD, ISTORE) {
			@Override
			public String typeDesc(String nameThis) {
				return Type.getDescriptor(int.class);
			}
		},
		/**
		 * We declare a local variable to indicate that a context-modifying userop has been invoked.
		 */
		CTXMOD("ctxmod", ILOAD, ISTORE) {
			@Override
			public String typeDesc(String nameThis) {
				return Type.getDescriptor(boolean.class);
			}

			@Override
			public void generateDeclCode(MethodVisitor mv, String nameThis, Label startLocals,
					Label endLocals) {
				super.generateDeclCode(mv, nameThis, startLocals, endLocals);
				mv.visitLdcInsn(0);
				mv.visitVarInsn(ISTORE, index());
			}
		};

		private final String varName;
		private final int opcodeLoad;
		private final int opcodeStore;

		private RunFixedLocal(String varName, int opcodeLoad, int opcodeStore) {
			this.varName = varName;
			this.opcodeLoad = opcodeLoad;
			this.opcodeStore = opcodeStore;
		}

		/**
		 * All of the runtime locals
		 */
		public static final List<FixedLocal> ALL = List.of(values());

		@Override
		public int index() {
			return ordinal();
		}

		@Override
		public String varName() {
			return varName;
		}

		@Override
		public int opcodeLoad() {
			return opcodeLoad;
		}

		@Override
		public int opcodeStore() {
			return opcodeStore;
		}
	}

	private final JitDataFlowModel dfm;
	private final JitVarScopeModel vsm;
	private final JitTypeModel tm;

	private final SleighLanguage language;
	private final Endian endian;

	private int nextLocal = RunFixedLocal.ALL.size();
	private final Map<JitVal, VarHandler> handlers = new HashMap<>();
	private final Map<Varnode, VarHandler> handlersPerVarnode = new HashMap<>();
	private final NavigableMap<Address, JvmLocal> locals = new TreeMap<>();

	/**
	 * Construct the allocation model.
	 * 
	 * @param context the analysis context
	 * @param dfm the data flow moel
	 * @param vsm the variable scope model
	 * @param tm the type model
	 */
	public JitAllocationModel(JitAnalysisContext context, JitDataFlowModel dfm,
			JitVarScopeModel vsm, JitTypeModel tm) {
		this.dfm = dfm;
		this.vsm = vsm;
		this.tm = tm;

		this.endian = context.getEndian();
		this.language = context.getLanguage();

		allocate();
	}

	/**
	 * Reserve (allocate) one local for the given p-code variable
	 * 
	 * @param name the name of the JVM local
	 * @param type the p-code type represented by the local
	 * @param desc the variable's descriptor
	 * @return the allocated JVM local
	 */
	private JvmLocal genFreeLocal(String name, SimpleJitType type, VarDesc desc) {
		int i = nextLocal;
		if (type.javaType() == long.class || type.javaType() == double.class) {
			nextLocal += 2;
		}
		else {
			nextLocal += 1;
		}
		return new JvmLocal(i, name, type, desc.toVarnode());
	}

	/**
	 * Get the next free local index without reserving it
	 * 
	 * <p>
	 * This should be used by operator code generators <em>after</em> all the
	 * {@link JitBytesPcodeExecutorState state} bypassing local variables have been allocated. The
	 * variables should be scoped to that operator only, so that the ids used are freed for the next
	 * operator.
	 * 
	 * @return the next id
	 */
	public int nextFreeLocal() {
		return nextLocal;
	}

	/**
	 * Reserve (allocate) several locals for the given p-code variable
	 * 
	 * @param name a prefix to name each JVM local
	 * @param types a p-code type that describes what each local stores
	 * @param desc the (whole) variable's descriptor
	 * @return the allocated JVM locals from most to least significant
	 */
	private List<JvmLocal> genFreeLocals(String name, List<SimpleJitType> types,
			VarDesc desc) {
		JvmLocal[] result = new JvmLocal[types.size()];
		Iterable<SimpleJitType> it = language.isBigEndian()
				? types
				: () -> new ReverseListIterator<SimpleJitType>(types);
		long offset = desc.offset;
		int i = 0;
		for (SimpleJitType t : it) {
			VarDesc d = new VarDesc(desc.spaceId, offset, t.size(), t, language);
			result[i] = genFreeLocal(name + "_" + i, t, d);
			offset += t.size();
			i++;
		}
		return List.of(result);
	}

	/**
	 * A content for assigning a type to a varnode
	 * 
	 * <p>
	 * Because several SSA variables can share one varnode, we let each cast a vote to determine the
	 * JVM type of the local(s) allocated to it.
	 * 
	 * @implNote <b>TODO</b>: This type contest could receive more detailed information from the
	 *           type model, but perhaps that's more work than it's worth. I would have to
	 *           communicate all votes, not just the winner....
	 */
	record TypeContest(Map<JitType, Integer> map) {
		/**
		 * Start a new contest
		 */
		public TypeContest() {
			this(new HashMap<>());
		}

		/**
		 * Cast a vote for the given type
		 * 
		 * @param type the type
		 */
		public void vote(JitType type) {
			map.compute(type.ext(), (t, v) -> v == null ? 1 : v + 1);
		}

		/**
		 * Choose the winner, favoring integral types
		 * 
		 * @return the winning type
		 */
		public JitType winner() {
			int max = map.values().stream().max(Integer::compare).get();
			return map.entrySet()
					.stream()
					.filter(e -> e.getValue() == max)
					.map(Map.Entry::getKey)
					.sorted(Comparator.comparing(JitType::pref))
					.findFirst()
					.get();
		}
	}

	private final Map<Varnode, TypeContest> typeContests = new HashMap<>();

	/**
	 * Create a handler for the variable stored by the one given local
	 * 
	 * @param local the local
	 * @return the handler
	 */
	private OneLocalVarHandler createOneLocalHandler(JvmLocal local) {
		return switch (local.type) {
			case IntJitType t -> new IntVarAlloc(local, t);
			case LongJitType t -> new LongVarAlloc(local, t);
			case FloatJitType t -> new FloatVarAlloc(local, t);
			case DoubleJitType t -> new DoubleVarAlloc(local, t);
			default -> throw new AssertionError();
		};
	}

	/**
	 * Create a handler for a multi-part or subpiece varnode
	 * 
	 * @param vn the varnode
	 * @return a handler to access the value of the given varnode, as allocated in one or more
	 *         locals.
	 */
	private VarHandler createComplicatedHandler(Varnode vn) {
		Entry<Address, JvmLocal> leftEntry = locals.floorEntry(vn.getAddress());
		assert overlapsLeft(leftEntry.getValue().vn, vn);
		Address min = leftEntry.getKey();
		NavigableMap<Address, JvmLocal> sub = locals.subMap(min, true, maxAddr(vn), true);

		List<MultiLocalPart> parts = new ArrayList<>();
		for (JvmLocal local : sub.values()) {
			int offset = (int) switch (endian) {
				case BIG -> maxAddr(leftEntry.getValue().vn).subtract(maxAddr(vn));
				case LITTLE -> vn.getAddress().subtract(leftEntry.getKey());
			};
			parts.add(new MultiLocalPart(local, offset));
		}
		return new MultiLocalVarHandler(parts, JitTypeBehavior.INTEGER.type(vn.getSize()));
	}

	/**
	 * Get (creating if necessary) the handler for the given variable's varnode.
	 * 
	 * @param vv the variable
	 * @return the handler
	 */
	private VarHandler getOrCreateHandlerForVarnodeVar(JitVarnodeVar vv) {
		return handlersPerVarnode.computeIfAbsent(vv.varnode(), vn -> {
			JvmLocal oneLocal = locals.get(vn.getAddress());
			if (oneLocal != null && oneLocal.vn.equals(vn)) {
				return createOneLocalHandler(oneLocal);
			}
			return createComplicatedHandler(vn);
		});
	}

	/**
	 * Get (creating if necessary) the handler for the given value
	 * 
	 * @param v the value
	 * @return a handler for the value's varnode, if it is a register or unique; otherwise, the
	 *         dummy handler
	 */
	private VarHandler createHandler(JitVal v) {
		if (v instanceof JitConstVal) {
			return NoHandler.INSTANCE;
		}
		if (v instanceof JitFailVal) {
			return NoHandler.INSTANCE;
		}
		if (v instanceof JitMemoryVar) {
			return NoHandler.INSTANCE;
		}
		if (v instanceof JitVarnodeVar vv) {
			return getOrCreateHandlerForVarnodeVar(vv);
		}
		throw new AssertionError();
	}

	/**
	 * Perform the actual allocations
	 */
	private void allocate() {
		for (JitVal v : dfm.allValues()) {
			if (v instanceof JitVarnodeVar vv && !(v instanceof JitMemoryVar)) {
				Varnode vn = vv.varnode();
				Varnode coalesced = vsm.getCoalesced(vn);
				TypeContest tc = typeContests.computeIfAbsent(coalesced, __ -> new TypeContest());
				if (vn.equals(coalesced)) {
					tc.vote(tm.typeOf(v));
				}
				else {
					tc.vote(JitTypeBehavior.INTEGER.type(coalesced.getSize()));
				}
			}
		}

		for (Map.Entry<Varnode, TypeContest> entry : typeContests.entrySet()
				.stream()
				.sorted(Comparator.comparing(e -> e.getKey().getAddress()))
				.toList()) {
			VarDesc desc = VarDesc.fromVarnode(entry.getKey(), entry.getValue().winner(), language);
			switch (desc.type()) {
				case SimpleJitType t -> {
					locals.put(entry.getKey().getAddress(), genFreeLocal(desc.name(), t, desc));
				}
				case MpIntJitType t -> {
					for (JvmLocal leg : genFreeLocals(desc.name(), t.legTypes(), desc)) {
						locals.put(leg.vn.getAddress(), leg);
					}
				}
				default -> throw new AssertionError();
			}
		}

		for (JitVal v : dfm.allValuesSorted()) {
			handlers.put(v, createHandler(v));
		}
	}

	/**
	 * Get the handler for the given value (constant or variable in the use-def graph)
	 * 
	 * @param v the value
	 * @return the handler
	 */
	public VarHandler getHandler(JitVal v) {
		return handlers.get(v);
	}

	/**
	 * Get all of the locals allocated
	 * 
	 * @return the locals
	 */
	public Collection<JvmLocal> allLocals() {
		return locals.values();
	}

	/**
	 * Get all of the locals allocated for the given varnode
	 * 
	 * 
	 * @implNote This is used by the code generator to birth and retire the local variables, given
	 *           that scope is analyzed in terms of varnodes.
	 * @param vn the varnode
	 * @return the locals
	 */
	public Collection<JvmLocal> localsForVn(Varnode vn) {
		Address min = vn.getAddress();
		Address floor = locals.floorKey(min);
		if (floor != null) {
			min = floor;
		}
		return locals.subMap(min, true, maxAddr(vn), true).values();
	}
}
