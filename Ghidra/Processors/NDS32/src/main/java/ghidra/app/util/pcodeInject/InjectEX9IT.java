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
package ghidra.app.util.pcodeInject;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;

/**
 * Pcode fixup for the NDS32 {@code ex9.it} instruction.  Reads the tracked
 * {@code itb} value, fetches the 4-byte IT entry at {@code (itb & ~3) + imm * 4},
 * disassembles it, and returns its pcode.  PC-relative loads in the IT entry
 * resolve against the ex9.it site PC; branches/calls are re-decoded at PC=0
 * (per the NDS32 manual) to recover the absolute target.  Returns null when
 * itb is untracked or the IT entry is unmapped.
 */
public class InjectEX9IT extends InjectPayloadCallother {
	private static final int IT_ENTRY_LENGTH = 4;

	private final SleighLanguage language;

	// Keyed on absolute IT-entry address; bytes stored on the entry detect stale
	// hits after a memory edit.  Outer map is weak so closing a program drops
	// its cache; inner map is concurrent.
	private final Map<Program, ConcurrentHashMap<Long, CacheEntry>> programCaches =
		Collections.synchronizedMap(new WeakHashMap<>());

	/**
	 * Cached parse of a single IT entry.  Exposed so
	 * {@link ghidra.app.plugin.core.analysis.NDS32ITBAnalyzer} can share the cache.
	 */
	public static final class CacheEntry {
		public final byte[] bytes;
		public final InstructionPrototype proto;
		public final boolean rebuildAtZero;

		CacheEntry(byte[] bytes, InstructionPrototype proto, boolean rebuildAtZero) {
			this.bytes = bytes;
			this.proto = proto;
			this.rebuildAtZero = rebuildAtZero;
		}
	}

	public InjectEX9IT(String sourceName, SleighLanguage language) {
		super(sourceName);
		this.language = language;
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		Register itbReg = language.getRegister("itb");
		if (itbReg == null) {
			return null;
		}

		ProgramContext programContext = program.getProgramContext();
		BigInteger itb = programContext.getValue(itbReg, con.baseAddr, false);
		if (itb == null) {
			return null;
		}

		if (con.inputlist == null || con.inputlist.isEmpty()) {
			return null;
		}
		long imm = con.inputlist.get(0).getOffset();

		long memOffset = (itb.longValue() & ~0b11L) + imm * IT_ENTRY_LENGTH;
		Address fetchAddr = con.baseAddr.getNewAddress(memOffset);

		byte[] bytes = new byte[IT_ENTRY_LENGTH];
		Memory memory = program.getMemory();
		try {
			if (memory.getBytes(fetchAddr, bytes) != Array.getLength(bytes)) {
				return null;
			}
		}
		catch (Exception e) {
			return null;
		}

		try {
			Address site = con.baseAddr;
			Language lang = program.getLanguage();

			CacheEntry entry = lookupOrParse(program, programContext, lang, fetchAddr, bytes);
			if (entry == null) {
				return null;
			}

			// PcodeOp SEQNUM addresses depend on the PseudoInstruction address,
			// so we cache the prototype but rebuild the instruction per-site.
			PseudoDisassemblerContext disCtx = new PseudoDisassemblerContext(programContext);
			MemBuffer buf = new ByteMemBufferImpl(site, entry.bytes, lang.isBigEndian());
			disCtx.flowStart(site);
			if (entry.rebuildAtZero) {
				Address zero = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
				PseudoInstruction reloc = new PseudoInstruction(
					program.getAddressFactory(), zero, entry.proto, buf, disCtx);
				return reloc.getPcode();
			}
			PseudoInstruction probe =
				new PseudoInstruction(program, site, entry.proto, buf, disCtx);
			return probe.getPcode();
		}
		catch (AddressOverflowException e) {
			return null;
		}
		catch (Exception e) {
			return null;
		}
	}

	/**
	 * Look up the parsed prototype for an IT entry, parsing and caching on miss.
	 * Public so {@link ghidra.app.plugin.core.analysis.NDS32ITBAnalyzer} can
	 * share the cache and avoid re-parsing each unique entry.
	 *
	 * @return the cached entry, or {@code null} if the bytes don't decode
	 *     to a valid non-{@code ex9.it} instruction.
	 */
	public CacheEntry lookupOrParse(Program program, ProgramContext programContext,
			Language lang, Address fetchAddr, byte[] bytes) throws Exception {
		ConcurrentHashMap<Long, CacheEntry> cache =
			programCaches.computeIfAbsent(program, p -> new ConcurrentHashMap<>());
		long key = fetchAddr.getOffset();
		CacheEntry cached = cache.get(key);
		if (cached != null && Arrays.equals(cached.bytes, bytes)) {
			return cached;
		}

		PseudoDisassemblerContext disCtx = new PseudoDisassemblerContext(programContext);
		MemBuffer buf = new ByteMemBufferImpl(fetchAddr, bytes, lang.isBigEndian());
		disCtx.flowStart(fetchAddr);
		InstructionPrototype proto = lang.parse(buf, disCtx, false);
		if (proto == null) {
			return null;
		}
		PseudoInstruction probe = new PseudoInstruction(program, fetchAddr, proto, buf, disCtx);
		if (probe.getMnemonicString().equalsIgnoreCase("ex9.it")) {
			// Nested ex9.it would raise Reserved Instruction Exception in hardware.
			return null;
		}
		FlowType ft = proto.getFlowType(probe);
		boolean rebuildAtZero = ft.isCall() || ft.isJump();

		CacheEntry entry = new CacheEntry(bytes.clone(), proto, rebuildAtZero);
		cache.put(key, entry);
		return entry;
	}

	/**
	 * Drop cached IT entries so re-analysis sees fresh pcode at every ex9.it site.
	 * Called by the ITB analyzer when an ITB value change is detected.
	 *
	 * @param program if non-null, drop only that program's cache; if null, drop everything.
	 */
	public void invalidateCache(Program program) {
		synchronized (programCaches) {
			if (program == null) {
				programCaches.clear();
			}
			else {
				programCaches.remove(program);
			}
		}
	}
}
