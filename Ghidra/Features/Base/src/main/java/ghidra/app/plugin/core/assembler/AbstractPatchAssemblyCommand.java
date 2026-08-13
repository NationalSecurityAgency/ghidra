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
package ghidra.app.plugin.core.assembler;

import java.io.IOException;
import java.util.List;

import ghidra.app.plugin.assembler.*;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.Command;
import ghidra.program.disassemble.ReDisassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractPatchAssemblyCommand<T extends Program> extends BackgroundCommand<T> {
	protected final Assembler asm;
	protected final List<String> lines;
	protected final Address entry;
	protected final RegisterValue initialContext;

	private AddressSetView set;
	private Address next;
	protected String status = "Assembling";

	public AbstractPatchAssemblyCommand(Assembler asm, List<String> lines, Address entry,
			RegisterValue initialContext) {
		this.asm = asm;
		this.lines = lines;
		this.entry = entry;
		this.initialContext = initialContext;
	}

	public AbstractPatchAssemblyCommand(Assembler asm, String string, Address entry,
			RegisterValue initialContext) {
		this(asm, string.lines().toList(), entry, initialContext);
	}

	abstract protected Command<T> newDisassembleCommand(AddressSetView set, T program);

	public AddressSetView assemble(T program, TaskMonitor monitor)
			throws CancelledException, IOException, MemoryAccessException, AssemblyException {
		monitor.setMessage("Constructing Assembler");
		monitor.checkCancelled();
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry, initialContext);

		monitor.initialize(lines.size(), "Assembling");
		for (String line : lines) {
			if (line.isBlank()) {
				continue;
			}
			// LATER: Data directives? Label placement?
			try {
				buf.assemble(line);
				monitor.increment();
			}
			catch (AssemblySyntaxException | AssemblySemanticException e) {
				throw new AssemblyException("Could not assemble: %s".formatted(line), e);
			}
		}

		monitor.initialize(0, "Placing bytes");
		monitor.checkCancelled();
		AddressSet set = new AddressSet(entry, buf.getNext().previous());
		// Get the command before we modify the memory/listing, so it can inspect things
		Command<T> dis = newDisassembleCommand(set, program);

		program.getListing()
				.clearCodeUnits(set.getMinAddress(), set.getMaxAddress(), true, monitor);
		program.getMemory().setBytes(entry, buf.getBytes());

		monitor.setMessage("Disassembling");
		monitor.checkCancelled();

		// Might not succeed...
		dis.applyTo(program);

		monitor.setMessage("Repairing disassembly");
		monitor.checkCancelled();
		ReDisassembler redis = new ReDisassembler(program);
		AddressSet seeds = new AddressSet();
		for (Instruction ins : program.getListing().getInstructions(set, true)) {
			for (Address seed : ins.getFlows()) {
				seeds.add(seed);
			}
		}
		InstructionIterator lastIt = program.getListing().getInstructions(set, false);
		Instruction last = lastIt.hasNext() ? lastIt.next() : null;
		if (last != null && last.getFlowType().hasFallthrough()) {
			Address fall = last.getMaxAddress().next();
			if (fall != null) {
				seeds.add(fall);
			}
		}
		redis.disassemble(seeds, monitor);
		return set;
	}

	@Override
	public final boolean applyTo(T program, TaskMonitor monitor) {
		try {
			set = assemble(program, monitor);
			next = set.getMaxAddress().next();
			return true;
		}
		catch (CancelledException e) {
			return false;
		}
		catch (MemoryAccessException | IOException e) {
			throw new AssertionError();
		}
		catch (AssemblyException e) {
			status = e.getMessage();
			return false;
		}
	}

	@Override
	public String getStatusMsg() {
		return status;
	}

	@Override
	public String getName() {
		return "Assemble";
	}

	public AddressSetView getSet() {
		return set;
	}

	public Address getNext() {
		return next;
	}
}
