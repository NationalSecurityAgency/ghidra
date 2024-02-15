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
package ghidra.app.plugin.assembler.sleigh;

import static ghidra.program.util.ProgramEvent.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;

import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.AssemblySelector.Selection;
import ghidra.app.plugin.assembler.sleigh.parse.*;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractSleighAssembler<RP extends AssemblyResolvedPatterns>
		implements GenericAssembler<RP> {
	protected static final DbgTimer dbg = DbgTimer.INACTIVE;

	protected class ListenerForSymbolsRefresh implements DomainObjectListener {
		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			if (ev.contains(SYMBOL_ADDED, SYMBOL_ADDRESS_CHANGED, SYMBOL_REMOVED, SYMBOL_RENAMED)) {
				synchronized (lock) {
					symbols = null;
				}
			}
		}
	}

	protected final Object lock = new Object();

	protected final SleighLanguage lang;
	protected final Program program;
	protected final Listing listing;
	protected final Memory memory;

	protected final AbstractAssemblyResolutionFactory<RP, ?> factory;
	protected final AssemblySelector selector;
	protected final AssemblyParser parser;
	protected final AssemblyDefaultContext defaultContext;
	protected final AssemblyContextGraph ctxGraph;

	protected AssemblyNumericSymbols symbols;

	protected AbstractSleighAssembler(AbstractAssemblyResolutionFactory<RP, ?> factory,
			AssemblySelector selector, Program program, AssemblyParser parser,
			AssemblyDefaultContext defaultContext, AssemblyContextGraph ctxGraph) {
		this.factory = factory;
		this.selector = selector;
		this.program = program;
		this.parser = parser;
		this.defaultContext = defaultContext;
		this.ctxGraph = ctxGraph;

		this.lang = (SleighLanguage) program.getLanguage();
		this.listing = program.getListing();
		this.memory = program.getMemory();
	}

	protected AbstractSleighAssembler(AbstractAssemblyResolutionFactory<RP, ?> factory,
			AssemblySelector selector, SleighLanguage lang, AssemblyParser parser,
			AssemblyDefaultContext defaultContext, AssemblyContextGraph ctxGraph) {
		this.factory = factory;
		this.selector = selector;
		this.lang = lang;
		this.parser = parser;
		this.defaultContext = defaultContext;
		this.ctxGraph = ctxGraph;

		this.program = null;
		this.listing = null;
		this.memory = null;
	}

	protected abstract AbstractAssemblyTreeResolver<RP> newResolver(Address at,
			AssemblyParseBranch tree, AssemblyPatternBlock ctx);

	@Override
	public Instruction patchProgram(AssemblyResolvedPatterns res, Address at)
			throws MemoryAccessException {
		if (!res.getInstruction().isFullMask()) {
			throw new AssemblySelectionError("Selected instruction must have a full mask.");
		}
		return patchProgram(res.getInstruction().getVals(), at).next();
	}

	@Override
	public InstructionIterator patchProgram(byte[] insbytes, Address at)
			throws MemoryAccessException {
		if (insbytes.length == 0) {
			return listing.getInstructions(new AddressSet(), true);
		}
		Address end = at.add(insbytes.length - 1);
		listing.clearCodeUnits(at, end, false);
		memory.setBytes(at, insbytes);
		AddressSet set = new AddressSet(at, end);

		// Creating this at construction causes it to assess memory flags too early.
		Disassembler dis = Disassembler.getDisassembler(program, TaskMonitor.DUMMY,
			DisassemblerMessageListener.IGNORE);
		dis.disassemble(at, set);
		return listing.getInstructions(set, true);
	}

	@Override
	public InstructionIterator assemble(Address at, String... assembly)
			throws AssemblySyntaxException, AssemblySemanticException, MemoryAccessException,
			AddressOverflowException {
		Address start = at;
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		for (String part : assembly) {
			for (String line : part.split("\n")) {
				RegisterValue rv = program.getProgramContext().getDisassemblyContext(at);
				dbg.println(rv);
				AssemblyPatternBlock ctx = AssemblyPatternBlock.fromRegisterValue(rv);
				ctx = ctx.fillMask();
				byte[] insbytes = assembleLine(at, line, ctx);
				if (insbytes == null) {
					return null;
				}
				try {
					buf.write(insbytes);
				}
				catch (IOException e) {
					throw new AssertionError(e);
				}
				at = at.addNoWrap(insbytes.length);
			}
		}
		return patchProgram(buf.toByteArray(), start);
	}

	@Override
	public byte[] assembleLine(Address at, String line)
			throws AssemblySyntaxException, AssemblySemanticException {
		AssemblyPatternBlock ctx = defaultContext.getDefaultAt(at);
		ctx = ctx.fillMask();
		return assembleLine(at, line, ctx);
	}

	@Override
	public Collection<AssemblyParseResult> parseLine(String line) {
		return parser.parse(line, getNumericSymbols());
	}

	@Override
	public AssemblyResolutionResults resolveTree(AssemblyParseResult parse, Address at,
			AssemblyPatternBlock ctx) {
		if (parse.isError()) {
			AssemblyResolutionResults results = factory.newAssemblyResolutionResults();
			AssemblyParseErrorResult err = (AssemblyParseErrorResult) parse;
			results.add(factory.newErrorBuilder()
					.error(err.describeError())
					.description("Parsing")
					.build());
			return results;
		}

		AssemblyParseAcceptResult acc = (AssemblyParseAcceptResult) parse;
		AbstractAssemblyTreeResolver<RP> tr = newResolver(at, acc.getTree(), ctx);
		return tr.resolve();
	}

	@Override
	public AssemblyResolutionResults resolveTree(AssemblyParseResult parse, Address at) {
		AssemblyPatternBlock ctx = getContextAt(at);
		return resolveTree(parse, at, ctx);
	}

	@Override
	public AssemblyResolutionResults resolveLine(Address at, String line)
			throws AssemblySyntaxException {
		return resolveLine(at, line, getContextAt(at).fillMask());
	}

	@Override
	public AssemblyResolutionResults resolveLine(Address at, String line, AssemblyPatternBlock ctx)
			throws AssemblySyntaxException {

		if (!ctx.isFullMask()) {
			throw new AssemblyError(
				"Context must be fully-specified (full length, no shift, no unknowns)");
		}
		if (lang.getContextBaseRegister() != Register.NO_CONTEXT &&
			ctx.length() < lang.getContextBaseRegister().getMinimumByteSize()) {
			throw new AssemblyError(
				"Context must be fully-specified (full length, no shift, no unknowns)");
		}
		Collection<AssemblyParseResult> parse = parseLine(line);
		parse = selector.filterParse(parse);
		if (!parse.iterator().hasNext()) { // Iterator.isEmpty()???
			throw new AssemblySelectionError(
				"Must select at least one parse result. Report errors via AssemblySyntaxError");
		}
		AssemblyResolutionResults results = factory.newAssemblyResolutionResults();
		for (AssemblyParseResult p : parse) {
			results.absorb(resolveTree(p, at, ctx));
		}
		return results;
	}

	@Override
	public byte[] assembleLine(Address at, String line, AssemblyPatternBlock ctx)
			throws AssemblySemanticException, AssemblySyntaxException {
		AssemblyResolutionResults results = resolveLine(at, line, ctx);
		Selection sel = selector.select(results, ctx);
		if (sel == null) {
			throw new AssemblySelectionError(
				"Must select exactly one instruction. Report errors via AssemblySemanticError");
		}
		if (!sel.ins().isFullMask()) {
			throw new AssemblySelectionError("Selected instruction must have a full mask.");
		}
		if (sel.ctx().combine(ctx) == null) {
			throw new AssemblySelectionError("Selected instruction must have compatible context");
		}
		return sel.ins().getVals();
	}

	/**
	 * A convenience to obtain assembly symbols
	 * 
	 * @return the map
	 */
	protected AssemblyNumericSymbols getNumericSymbols() {
		synchronized (lock) {
			if (symbols != null) {
				return symbols;
			}
			if (program == null) {
				symbols = AssemblyNumericSymbols.fromLanguage(lang);
			}
			else {
				symbols = AssemblyNumericSymbols.fromProgram(program);
			}
			return symbols;
		}
	}

	@Override
	public AssemblyPatternBlock getContextAt(Address addr) {
		if (program != null) {
			RegisterValue rv = program.getProgramContext().getDisassemblyContext(addr);
			return AssemblyPatternBlock.fromRegisterValue(rv);
		}
		return defaultContext.getDefaultAt(addr);
	}
}
