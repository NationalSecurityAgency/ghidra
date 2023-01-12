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
package ghidra.app.plugin.core.debug.stack;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;

/**
 * A symbolic value tailored for stack unwind analysis
 * 
 * <p>
 * The goals of stack unwind analysis are 1) to figure the stack depth at a particular instruction,
 * 2) to figure the locations of saved registers on the stack, 3) to figure the location of the
 * return address, whether in a register or on the stack, and 4) to figure the change in stack depth
 * from calling the function. Not surprisingly, these are the fields of {@link UnwindInfo}. To these
 * ends, symbols may have only one of the following forms:
 * 
 * <ul>
 * <li>An opaque value: {@link OpaqueSym}, to represent expressions too complex.</li>
 * <li>A constant: {@link ConstSym}, to fold constants and use as offsets.</li>
 * <li>A register: {@link RegisterSym}, to detect saved registers and to generate stack offsets</li>
 * <li>A stack offset, i.e., SP + c: {@link StackOffsetSym}, to fold offsets, detect stack depth,
 * and to generate stack dereferences</li>
 * <li>A dereference of a stack offset, i.e., *(SP + c): {@link StackDerefSym}, to detect restored
 * registers and return address location</li>
 * </ul>
 * 
 * <p>
 * The rules are fairly straightforward:
 * 
 * <ul>
 * <li>a:Opaque + b:Any => Opaque()</li>
 * <li>a:Const + b:Const => Const(val=a.val + b.val)</li>
 * <li>a:Const + b:Register(reg==SP) => Offset(offset=a.val)</li>
 * <li>a:Offset: + b:Const => Offset(offset=a.offset + b.val)</li>
 * <li>*a:Offset => Deref(offset=a.offset)</li>
 * <li>*a:Register(reg==SP) => Deref(offset=0)</li>
 * </ul>
 * 
 * <p>
 * Some minute operations are omitted for clarity. Any other operation results in Opaque(). There is
 * a small fault in that Register(reg=SP) and Offset(offset=0) represent the same thing, but with
 * some extra bookkeeping, it's not too terrible. By interpreting p-code and then examining the
 * symbolic machine state, simple movement of data between registers and the stack can be
 * summarized.
 */
sealed interface Sym {
	/**
	 * Get the opaque symbol
	 * 
	 * @return the symbol
	 */
	static Sym opaque() {
		return OpaqueSym.OPAQUE;
	}

	/**
	 * Add this and another symbol with the given compiler for context
	 * 
	 * @param cSpec the compiler specification
	 * @param in2 the second symbol
	 * @return the resulting symbol
	 */
	Sym add(CompilerSpec cSpec, Sym in2);

	/**
	 * Subtract another symbol from this with the given compiler for context
	 * 
	 * @param cSpec the compiler specification
	 * @param in2 the second symbol
	 * @return the resulting symbol
	 */
	default Sym sub(CompilerSpec cSpec, Sym in2) {
		return add(cSpec, in2.twosComp());
	}

	/**
	 * Negate this symbol
	 * 
	 * @return the resulting symbol
	 */
	Sym twosComp();

	/**
	 * Get the size of this symbol with the given compiler for context
	 * 
	 * @param cSpec the compiler specification
	 * @return the size in bytes
	 */
	long sizeOf(CompilerSpec cSpec);

	/**
	 * Get a constant symbol
	 * 
	 * @param value the value
	 * @return the constant (with size 8 bytes)
	 */
	static Sym constant(long value) {
		return new ConstSym(value, 8);
	}

	/**
	 * When this symbol is used as the offset in a given address space, translate it to the address
	 * if possible
	 * 
	 * <p>
	 * The address will be used by the state to retrieve the appropriate (symbolic) value, possibly
	 * generating a fresh symbol. If the address is {@link Address#NO_ADDRESS}, then the state will
	 * yield the opaque symbol. For sets, the state will store the given symbolic value at the
	 * address. If it is {@link Address#NO_ADDRESS}, then the value is ignored.
	 * 
	 * @param space the space being dereferenced
	 * @param cSpec the compiler specification
	 * @return the address, or {@link Address#NO_ADDRESS}
	 */
	Address addressIn(AddressSpace space, CompilerSpec cSpec);

	/**
	 * The singleton opaque symbol
	 */
	public enum OpaqueSym implements Sym {
		/**
		 * Singleton instance
		 */
		OPAQUE;

		@Override
		public Sym add(CompilerSpec cSpec, Sym in2) {
			return this;
		}

		@Override
		public Sym twosComp() {
			return this;
		}

		@Override
		public long sizeOf(CompilerSpec cSpec) {
			throw new UnsupportedOperationException();
		}

		@Override
		public Address addressIn(AddressSpace space, CompilerSpec cSpec) {
			return Address.NO_ADDRESS;
		}
	}

	/**
	 * A constant symbol
	 */
	public record ConstSym(long value, int size) implements Sym {
		@Override
		public Sym add(CompilerSpec cSpec, Sym in2) {
			if (in2 instanceof ConstSym const2) {
				return new ConstSym(value + const2.value, size);
			}
			if (in2 instanceof RegisterSym reg2) {
				if (reg2.register() == cSpec.getStackPointer()) {
					return new StackOffsetSym(value);
				}
				return Sym.opaque();
			}
			if (in2 instanceof StackOffsetSym off2) {
				return new StackOffsetSym(value + off2.offset);
			}
			return Sym.opaque();
		}

		@Override
		public Sym twosComp() {
			return new ConstSym(-value, size);
		}

		@Override
		public long sizeOf(CompilerSpec cSpec) {
			return size;
		}

		@Override
		public Address addressIn(AddressSpace space, CompilerSpec cSpec) {
			if (space.isConstantSpace() || space.isRegisterSpace() || space.isUniqueSpace()) {
				return space.getAddress(value);
			}
			return Address.NO_ADDRESS;
		}
	}

	/**
	 * A register symbol
	 */
	public record RegisterSym(Register register) implements Sym {
		@Override
		public Sym add(CompilerSpec cSpec, Sym in2) {
			if (in2 instanceof ConstSym const2) {
				return const2.add(cSpec, this);
			}
			return Sym.opaque();
		}

		@Override
		public Sym twosComp() {
			return Sym.opaque();
		}

		@Override
		public long sizeOf(CompilerSpec cSpec) {
			return register.getMinimumByteSize();
		}

		@Override
		public Address addressIn(AddressSpace space, CompilerSpec cSpec) {
			if (register != cSpec.getStackPointer()) {
				return Address.NO_ADDRESS;
			}
			if (space != cSpec.getStackBaseSpace()) {
				return Address.NO_ADDRESS;
			}
			return cSpec.getStackSpace().getAddress(0);
		}
	}

	/**
	 * A stack offset symbol
	 * 
	 * <p>
	 * This represents a value in the form SP + c, where SP is the stack pointer register and c is a
	 * constant.
	 */
	public record StackOffsetSym(long offset) implements Sym {
		@Override
		public Sym add(CompilerSpec cSpec, Sym in2) {
			if (in2 instanceof ConstSym const2) {
				return new StackOffsetSym(offset + const2.value());
			}
			return Sym.opaque();
		}

		@Override
		public Sym twosComp() {
			return Sym.opaque();
		}

		@Override
		public long sizeOf(CompilerSpec cSpec) {
			return cSpec.getStackPointer().getMinimumByteSize();
		}

		@Override
		public Address addressIn(AddressSpace space, CompilerSpec cSpec) {
			if (space != cSpec.getStackBaseSpace()) {
				return Address.NO_ADDRESS;
			}
			return cSpec.getStackSpace().getAddress(offset);
		}
	}

	/**
	 * A stack dereference symbol
	 * 
	 * <p>
	 * This represents a dereferenced {@link StackOffsetSym} (or the dereferenced stack pointer
	 * register, in which is treated as a stack offset of 0).
	 */
	public record StackDerefSym(long offset, int size) implements Sym {
		@Override
		public Sym add(CompilerSpec cSpec, Sym in2) {
			return Sym.opaque();
		}

		@Override
		public Sym twosComp() {
			return Sym.opaque();
		}

		@Override
		public long sizeOf(CompilerSpec cSpec) {
			return size;
		}

		@Override
		public Address addressIn(AddressSpace space, CompilerSpec cSpec) {
			return Address.NO_ADDRESS;
		}
	}
}
