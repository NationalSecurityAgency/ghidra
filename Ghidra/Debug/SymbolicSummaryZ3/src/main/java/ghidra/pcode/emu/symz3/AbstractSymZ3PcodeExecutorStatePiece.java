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
import java.util.stream.Stream;

import com.microsoft.z3.Context;

import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.pcode.emu.symz3.plain.SymZ3Preconditions;
import ghidra.pcode.emu.symz3.plain.SymZ3Space;
import ghidra.pcode.exec.ConcretionError;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
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
 *
 * @param <S> the type of spaces
 */
public abstract class AbstractSymZ3PcodeExecutorStatePiece<S extends SymZ3Space>
		extends AbstractSymZ3OffsetPcodeExecutorStatePiece<S>
		implements InternalSymZ3RecordsPreconditions, InternalSymZ3RecordsExecution {

	/**
	 * The map from address space to storage space
	 * 
	 * <p>
	 * While the concept is introduced in the super class, we're not required to actually use one.
	 * We just have to implement {@link #getForSpace(AddressSpace, boolean)}. Nevertheless, the
	 * provided map is probably the best way, so we'll follow the pattern.
	 */
	protected final AbstractSpaceMap<S> spaceMap = newSpaceMap(this.language);

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
	 */
	public AbstractSymZ3PcodeExecutorStatePiece(Language language,
			PcodeArithmetic<SymValueZ3> addressArithmetic, PcodeArithmetic<SymValueZ3> arithmetic) {
		super(language, addressArithmetic, arithmetic);
	}

	/**
	 * Extension point: Create the actual space map
	 * 
	 * <p>
	 * This will need to be implemented by each state piece, i.e., non-abstract derivating class.
	 * The space map will provide instances of {@code <S>}, which will provide the actual (extended)
	 * storage logic.
	 * 
	 * @return the space map
	 */
	protected abstract AbstractSpaceMap<S> newSpaceMap(Language language);

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
	protected S getForSpace(AddressSpace space, boolean toWrite) {
		return spaceMap.getForSpace(space, toWrite);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Because the super class places no bound on {@code <S>}, we have to provide the delegation to
	 * the storage space.
	 */
	@Override
	protected void setInSpace(SymZ3Space space, SymValueZ3 offset, int size, SymValueZ3 val) {
		space.set(offset, size, val);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Because the super class places no bound on {@code <S>}, we have to provide the delegation to
	 * the storage space.
	 */
	@Override
	protected SymValueZ3 getFromSpace(SymZ3Space space, SymValueZ3 offset, int size) {
		return space.get(offset, size);
	}

	public String printableSummary() {
		StringBuilder result = new StringBuilder();
		for (S space : spaceMap.values()) {
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
		spaceMap.spaces.clear();
		preconditions.clear();
		ops.clear();
		instructions.clear();
	}

	protected Stream<String> streamPreconditions(Context ctx, Z3InfixPrinter z3p) {
		return preconditions.streamPreconditions(ctx, z3p);
	}
}
