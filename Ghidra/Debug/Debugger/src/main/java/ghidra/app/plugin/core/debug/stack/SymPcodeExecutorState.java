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

import java.util.*;

import ghidra.app.plugin.core.debug.stack.Sym.*;
import ghidra.app.plugin.core.debug.stack.SymStateSpace.SymEntry;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.util.Msg;

/**
 * A symbolic state for stack unwind analysis
 * 
 * <p>
 * This state can store symbols in stack, register, and unique spaces. It ignores physical memory,
 * since that is not typically used as temporary storage when moving values between registers and
 * stack. When an address is read that does not have an entry, the state will generate a fresh
 * symbol representing that address, if applicable.
 */
public class SymPcodeExecutorState implements PcodeExecutorState<Sym> {
	private final Program program;
	private final CompilerSpec cSpec;
	private final Language language;
	private final SymPcodeArithmetic arithmetic;

	private final SymStateSpace stackSpace;
	private final SymStateSpace registerSpace;
	private final SymStateSpace uniqueSpace;

	final Set<StackUnwindWarning> warnings = new LinkedHashSet<>();

	/**
	 * Construct a new state for the given program
	 */
	public SymPcodeExecutorState(Program program) {
		this.program = program;
		this.cSpec = program.getCompilerSpec();
		this.language = cSpec.getLanguage();
		this.arithmetic = new SymPcodeArithmetic(cSpec);
		this.stackSpace = new SymStateSpace();
		this.registerSpace = new SymStateSpace();
		this.uniqueSpace = new SymStateSpace();
	}

	protected SymPcodeExecutorState(Program program, SymPcodeArithmetic arithmetic,
			SymStateSpace stackSpace, SymStateSpace registerSpace, SymStateSpace uniqueSpace) {
		this.program = program;
		this.cSpec = program.getCompilerSpec();
		this.language = cSpec.getLanguage();
		this.arithmetic = new SymPcodeArithmetic(cSpec);
		this.stackSpace = stackSpace;
		this.registerSpace = registerSpace;
		this.uniqueSpace = uniqueSpace;
	}

	@Override
	public String toString() {
		return String.format("""
				%s[
				    cSpec=%s
				    stack=%s
				    registers=%s
				    unique=%s
				]
				""", getClass().getSimpleName(),
			cSpec.toString(),
			stackSpace.toString("    ", language),
			registerSpace.toString("    ", language),
			uniqueSpace.toString("    ", language));
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	@Override
	public PcodeArithmetic<Sym> getArithmetic() {
		return arithmetic;
	}

	@Override
	public void setVar(AddressSpace space, Sym offset, int size, boolean quantize,
			Sym val) {
		Address address = offset.addressIn(space, cSpec);
		if (address.isRegisterAddress()) {
			registerSpace.set(address, size, val);
		}
		else if (address.isUniqueAddress()) {
			uniqueSpace.set(address, size, val);
		}
		else if (address.isConstantAddress()) {
			throw new IllegalArgumentException();
		}
		else if (address.isStackAddress()) {
			stackSpace.set(address, size, val);
		}
		else {
			Msg.trace(this, "Ignoring set: space=" + space + ",offset=" + offset + ",size=" + size +
				",val=" + val);
		}
	}

	@Override
	public Sym getVar(AddressSpace space, Sym offset, int size, boolean quantize,
			Reason reason) {
		Address address = offset.addressIn(space, cSpec);
		if (address.isRegisterAddress()) {
			return registerSpace.get(address, size, arithmetic, language);
		}
		else if (address.isUniqueAddress()) {
			return uniqueSpace.get(address, size, arithmetic, language);
		}
		else if (address.isConstantAddress()) {
			return offset;
		}
		else if (address.isStackAddress()) {
			return stackSpace.get(address, size, arithmetic, language);
		}
		return Sym.opaque();
	}

	@Override
	public Map<Register, Sym> getRegisterValues() {
		return Map.of();
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		return new MemoryBufferImpl(program.getMemory(), address);
	}

	@Override
	public void clear() {
		registerSpace.clear();
		stackSpace.clear();
	}

	@Override
	public SymPcodeExecutorState fork() {
		return new SymPcodeExecutorState(program, arithmetic, stackSpace.fork(),
			registerSpace.fork(), uniqueSpace.fork());
	}

	/**
	 * Create a new state whose registers are forked from those of this state
	 */
	public SymPcodeExecutorState forkRegs() {
		return new SymPcodeExecutorState(program, arithmetic, new SymStateSpace(),
			registerSpace.fork(), new SymStateSpace());
	}

	public void dump() {
		System.err.println("Registers: ");
		registerSpace.dump("  ", language);
		System.err.println("Unique: ");
		uniqueSpace.dump("  ", language);
		System.err.println("Stack: ");
		stackSpace.dump("  ", language);
	}

	/**
	 * Examine this state's SP for the overall change in stack depth
	 * 
	 * <p>
	 * There are two cases:
	 * <ul>
	 * <li>SP:Register(reg==SP) => depth is 0</li>
	 * <li>SP:Offset => depth is SP.offset</li>
	 * </ul>
	 * 
	 * <p>
	 * If SP has any other form, the depth is unknown
	 * 
	 * @return the depth, or null if not known
	 */
	public Long computeStackDepth() {
		Register sp = cSpec.getStackPointer();
		Sym expr = getVar(sp, Reason.INSPECT);
		if (expr instanceof RegisterSym regVar && regVar.register() == sp) {
			return 0L;
		}
		if (expr instanceof StackOffsetSym stackOff) {
			return stackOff.offset();
		}
		return null;
	}

	/**
	 * Examine this state's PC for the location of the return address
	 * 
	 * <p>
	 * There are two cases:
	 * <ul>
	 * <li>PC:Register => location is PC.reg.address
	 * <li>PC:Deref => location is [Stack]:PC.offset
	 * </ul>
	 * 
	 * @return
	 */
	public Address computeAddressOfReturn() {
		Sym expr = getVar(language.getProgramCounter(), Reason.INSPECT);
		if (expr instanceof StackDerefSym stackVar) {
			return cSpec.getStackSpace().getAddress(stackVar.offset());
		}
		if (expr instanceof RegisterSym regVar) {
			return regVar.register().getAddress();
		}
		return null;
	}

	/**
	 * Compute a map of (saved) registers
	 * 
	 * <p>
	 * Any entry of the form (addr, v:Register) is collected as (v.register, addr). Note that the
	 * size of the stack entry is implied by the size of the register.
	 * 
	 * @return the map from register to address
	 */
	public Map<Register, Address> computeMapUsingStack() {
		Map<Register, Address> result = new HashMap<>();
		for (SymEntry ent : stackSpace.map.values()) {
			if (ent.isTruncated()) {
				continue;
			}
			if (!(ent.sym() instanceof RegisterSym regVar)) {
				continue;
			}
			result.put(regVar.register(), ent.entRange().getMinAddress());
		}
		return result;
	}

	/**
	 * Compute the map of (restored) registers
	 * 
	 * <p>
	 * Any entry of the form (reg, v:Deref) is collected as (reg, [Stack]:v.offset). Note that the
	 * size of the stack entry is implied by the size of the register.
	 * 
	 * @return
	 */
	public Map<Register, Address> computeMapUsingRegisters() {
		Map<Register, Address> result = new HashMap<>();
		for (SymEntry ent : registerSpace.map.values()) {
			if (ent.isTruncated()) {
				continue;
			}
			if (!(ent.sym() instanceof StackDerefSym stackVar)) {
				continue;
			}
			Register register = ent.getRegister(language);
			if (register == null) {
				continue;
			}
			result.put(register, cSpec.getStackSpace().getAddress(stackVar.offset()));
		}
		return result;
	}
}
