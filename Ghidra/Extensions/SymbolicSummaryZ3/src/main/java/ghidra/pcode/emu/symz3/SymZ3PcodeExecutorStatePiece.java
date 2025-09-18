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
package ghidra.pcode.emu.symz3;

import java.io.PrintStream;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Stream;

import com.microsoft.z3.Context;

import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.pcode.emu.symz3.state.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.symz3.model.SymValueZ3;

/**
 * An abstract SymZ3 state piece
 *
 * <p>
 * Because we want to reduce code repetition, we use the type hierarchy to increase the capabilities
 * of the state piece as we progress from stand-alone to Debugger-integrated. The framework-provided
 * class from which this derives, however, introduces the idea of a space map, whose values have
 * type {@code <S>}. We'll be using types derived from {@link SymZ3Space}, which is where all the
 * storage logic is actually located. Because that logic is what we're actually extending with each
 * more capable state piece, we have to ensure that type can be substituted. Thus, we have to create
 * these abstract classes from which the actual state pieces are derived, leaving {@code <S>}
 * bounded, but unspecified.
 */
public class SymZ3PcodeExecutorStatePiece
		extends AbstractSymZ3OffsetPcodeExecutorStatePiece<SymZ3Space>
		implements InternalSymZ3RecordsPreconditions, InternalSymZ3RecordsExecution {

	protected final Map<AddressSpace, SymZ3Space> spaceMap = new HashMap<>();

	protected final SymZ3Preconditions preconditions = new SymZ3Preconditions();
	// LATER: These two are a recurring concern, and should be separated out
	protected final List<RecOp> ops = new ArrayList<RecOp>();
	protected final List<RecInstruction> instructions = new ArrayList<RecInstruction>();

	/**
	 * Create a state piece
	 * 
	 * @param language the emulator's language
	 * @param addressArithmetic the arithmetic for the address type
	 * @param arithmetic the arithmetic for the value type
	 * @param cb callbacks to receive emulation events
	 */
	public SymZ3PcodeExecutorStatePiece(Language language,
			PcodeArithmetic<SymValueZ3> addressArithmetic, PcodeArithmetic<SymValueZ3> arithmetic,
			PcodeStateCallbacks cb) {
		super(language, addressArithmetic, arithmetic, cb);
	}

	/**
	 * Create the SymZ3 piece
	 * 
	 * @param language the language of the emulator
	 * @param addressArithmetic the address arithmetic, likely taken from the concrete piece
	 * @param cb callbacks to receive emulation events
	 */
	public SymZ3PcodeExecutorStatePiece(Language language,
			PcodeArithmetic<SymValueZ3> addressArithmetic, PcodeStateCallbacks cb) {
		this(language, addressArithmetic, SymZ3PcodeArithmetic.forLanguage(language), cb);
	}

	protected SymZ3Space newSpace(AddressSpace space) {
		if (space.isConstantSpace()) {
			throw new AssertionError();
		}
		else if (space.isRegisterSpace()) {
			return new SymZ3RegisterSpace(language, space,
				SymZ3PcodeExecutorStatePiece.this);
		}
		else if (space.isUniqueSpace()) {
			return new SymZ3UniqueSpace();
		}
		else if (space.isLoadedMemorySpace()) {
			return new SymZ3MemorySpace(language, space, SymZ3PcodeExecutorStatePiece.this);
		}
		else {
			throw new AssertionError("not yet supported space: " + space.toString());
		}
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		throw new ConcretionError("Cannot make Symbolic concrete", purpose);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here, we just follow the pattern: delegate to the space map.
	 */
	@Override
	protected SymZ3Space getForSpace(AddressSpace space, boolean toWrite) {
		if (toWrite) {
			return spaceMap.computeIfAbsent(space, this::newSpace);
		}
		return spaceMap.get(space);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Because the super class places no bound on {@code <S>}, we have to provide the delegation to
	 * the storage space.
	 */
	@Override
	protected void setInSpace(SymZ3Space space, SymValueZ3 offset, int size, SymValueZ3 val,
			PcodeStateCallbacks cb) {
		space.set(offset, size, val, cb);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Because the super class places no bound on {@code <S>}, we have to provide the delegation to
	 * the storage space.
	 */
	@Override
	protected SymValueZ3 getFromSpace(SymZ3Space space, SymValueZ3 offset, int size,
			PcodeStateCallbacks cb) {
		return space.get(offset, size, cb);
	}

	@Override
	public Map<Register, SymValueZ3> getRegisterValues() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Entry<Long, SymValueZ3> getNextEntryInternal(AddressSpace space, long offset) {
		SymZ3Space s = getForSpace(space, false);
		if (s == null) {
			return null;
		}
		return s.getNextEntry(offset);
	}

	public String printableSummary() {
		StringBuilder result = new StringBuilder();
		for (SymZ3Space space : spaceMap.values()) {
			result.append(space.printableSummary());
		}
		result.append(this.preconditions.printableSummary());
		return result.toString();
	}

	public void printSymbolicSummary(PrintStream out) {
		out.println(this.printableSummary());
	}

	public Stream<Map.Entry<String, String>> streamValuations(Context ctx, Z3InfixPrinter z3p) {
		return spaceMap.values().stream().flatMap(s -> s.streamValuations(ctx, z3p));
	}

	@Override
	public void addPrecondition(String precondition) {
		preconditions.addPrecondition(precondition);
	}

	@Override
	public void addInstruction(SymZ3PcodeThread thread, Instruction instruction) {
		instructions.add(new RecInstruction(instructions.size(), thread, instruction));
	}

	@Override
	public List<RecInstruction> getInstructions() {
		return Collections.unmodifiableList(instructions);
	}

	@Override
	public void addOp(SymZ3PcodeThread thread, PcodeOp op) {
		ops.add(new RecOp(ops.size(), thread, op));
	}

	@Override
	public List<RecOp> getOps() {
		return Collections.unmodifiableList(ops);
	}

	@Override
	public List<String> getPreconditions() {
		return preconditions.getPreconditions();
	}

	@Override
	public void clear() {
		spaceMap.clear();
		preconditions.clear();
		ops.clear();
		instructions.clear();
	}

	protected Stream<String> streamPreconditions(Context ctx, Z3InfixPrinter z3p) {
		return preconditions.streamPreconditions(ctx, z3p);
	}
}
