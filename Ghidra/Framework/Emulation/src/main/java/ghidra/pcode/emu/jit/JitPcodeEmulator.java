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
package ghidra.pcode.emu.jit;

import java.lang.invoke.MethodHandles.Lookup;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.objectweb.asm.MethodTooLargeException;

import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.analysis.JitDataFlowModel;
import ghidra.pcode.emu.jit.analysis.JitDataFlowUseropLibrary;
import ghidra.pcode.emu.jit.decode.JitPassageDecoder;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPointPrototype;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassageClass;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

/**
 * An extension of {@link PcodeEmulator} that applies Just-in-Time (JIT) translation to accelerate
 * execution.
 * 
 * <p>
 * This is meant as a near drop-in replacement for the class it extends. Aside from some additional
 * configuration, and some annotations you might add to a {@link PcodeUseropLibrary}, if applicable,
 * you can simply replace {@code new PcodeEmulator()} with {@code new JitPcodeEmulator(...)}.
 * 
 * <h1>A JIT-Accelerated P-code Emulator for the Java Virtual Machine</h1>
 * 
 * <p>
 * There are two major tasks to achieving JIT-accelerated p-code emulation: 1) The translation of
 * p-code to a suitable target's machine language, and 2) The selection, decoding, and cache
 * management of passages of machine code translations. For our purposes, the target language is JVM
 * bytecode, which introduces some restrictions which make the translation process substantially
 * different than targeting native machine language.
 * 
 * <h2>Terminology</h2>
 * 
 * <p>
 * Because of the potential for confusion of terms with similar meanings from similar disciplines,
 * and to distinguish our particular use of the terms, we establish some definitions up front:
 * 
 * <ul>
 * 
 * <li><b>Basic block</b>: A block of <em>p-code</em> ops for which there are no branches into or
 * from, except at its top and bottom. Note that this definition pertains only to p-code ops in the
 * same passage. Branches into a block from ops generated elsewhere in the translation source need
 * not be considered. Note also that p-code basic blocks might not coincide with machine-code basic
 * blocks.</li>
 * 
 * <li><b>Bytecode</b>: Shorthand for "JVM bytecode." Others sometimes use this to mean any machine
 * code, but for us "bytecode" only refers to the JVM's machine code.</li>
 * 
 * <li><b>Decode context</b>: The input contextreg value for decoding an instruction. This is often
 * paired with an address to seed passages, identify an instruction's "location," and identify an
 * entry point.</li>
 * 
 * <li><b>Emulation host</b>: The machine or environment on which the emulation target is being
 * hosted. This is usually also the <b>translation target</b>. For our purposes, this is the JVM,
 * often the same JVM executing Ghidra.</li>
 * 
 * <li><b>Emulation target</b>: The machine being emulated. As opposed to the <b>translation
 * target</b> or <b>emulation host</b>. While this can include many aspects of a target platform, we
 * often just mean the Instruction Set Architecture (ISA, or <b>language</b>) of the machine.</li>
 * 
 * <li><b>Entry point</b>: An address (and contextreg value) by which execution may enter a passage.
 * In addition to the decode seed, the translator may expose many entries into a given passage,
 * usually at branch targets or the start of each basic block coinciding with an instruction.</li>
 * 
 * <li><b>Instruction</b>: A single machine-code instruction.</li>
 * 
 * <li><b>Machine code</b>: The sequence of bytes and/or decoded instructions executed by a
 * machine.</li>
 * 
 * <li><b>Passage</b>: A collection of strides connected by branches. Often each stride begins at
 * the target of some branch in another stride.</li>
 * 
 * <li><b>P-code</b>: An intermediate representation used by Ghidra in much of its analysis and
 * execution modeling. For our purposes, we mean "low p-code," which is the common language into
 * which the source machine code is translated before final translation to bytecode.</li>
 * 
 * <li><b>P-code op</b>: A single p-code operation. A single instruction usually generates several
 * p-code ops.</li>
 * 
 * <li><b>Stride</b>: A contiguous sequence of instructions (and their emitted p-code) connected by
 * fall-through. Note that conditional branches may appear in the middle of the stride. So long as
 * fall-through is possible, the stride may continue.</li>
 * 
 * <li><b>Translation source</b>: The machine code of the <b>emulation target</b> that is being
 * translated and subsequently executed by the <b>emulation host</b>.</li>
 * 
 * <li><b>Translation target</b>: The target of the JIT translation, usually the <b>emulation
 * host</b>. For our purposes, this is always JVM bytecode.</li>
 * 
 * <li><b>Varnode</b>: The triple (space,offset,size) giving the address and size of a variable in
 * the emulation target's machine state. This is distinct from a variable node (see {@link JitVal})
 * in the {@link JitDataFlowModel use-def} graph. The name "{@link Varnode}" is an unfortunate
 * inheritance from the Ghidra API, where they <em>can</em> represent genuine variable nodes in the
 * "high p-code" returned by the decompiler. However, the emulator consumes the "low p-code" where
 * varnodes are mere triples, which is how we use the term.</li>
 * 
 * </ul>
 * 
 * <h2>Just-in-Time Translation</h2>
 * <p>
 * For details of the translation process, see {@link JitCompiler}.
 * 
 * <h2>Translation Cache</h2>
 * <p>
 * This class, aside from overriding and replacing the state and thread objects with respective
 * extensions, manages a part of the translation cache. For reasons discussed in the translation
 * section, there are two levels of caching. Once a passage is translated into a classfile, it must
 * be loaded as a class and then instantiated for the thread executing it. Thus, at the machine (or
 * emulator) level, each translated passage's class is cached. Then, each thread caches its instance
 * of that class. When a thread encounters an address (and contextreg value) that it has not yet
 * translated, it requests that the emulator perform that translation. The details of this check are
 * described in {@link #getEntryPrototype(AddrCtx, JitPassageDecoder)} and
 * {@link JitPcodeThread#getEntry(AddrCtx)}.
 */
public class JitPcodeEmulator extends PcodeEmulator {

	/**
	 * The compiler which translates passages into JVM classes
	 */
	protected final JitCompiler compiler;
	/**
	 * A lookup to access non-public things
	 */
	private final Lookup lookup;

	/**
	 * This emulator's cache of passage translations, incl. all entry points.
	 * 
	 * <p>
	 * TODO: Invalidation of entries. One possible complication is any thread may still have an
	 * instance of one, and could possibly be executing it. Perhaps this could be a weak hash map,
	 * and they'll stay alive by virtue of the instances pointing to their classes? Still, we might
	 * like to impose a total size max, which would have to be implemented among the threads. Other
	 * reasons we may need to invalidate include:
	 * 
	 * <ol>
	 * <li>Self-modifying code (we'll probably want to provide a configuration toggle given how
	 * expensive that may become).</li>
	 * <li>Changes to the memory map. At the moment, however, the p-code emulator does not provide a
	 * memory management unit (MMU).</li>
	 * <li>Addition of a new inject by the user or script. This one's actually pretty likely. For
	 * now, we might just document that injects should not be changes once execution starts.</li>
	 * </ol>
	 */
	protected final Map<AddrCtx, CompletableFuture<EntryPointPrototype>> codeCache =
		new HashMap<>();

	/**
	 * Create a JIT-accelerated p-code emulator
	 * 
	 * @param language the emulation target langauge
	 * @param config configuration options for this emulator
	 * @param lookup a lookup in case the emulator (or its target) needs access to non-public
	 *            elements, e.g., to access a nested {@link PcodeUseropLibrary}.
	 */
	public JitPcodeEmulator(Language language, JitConfiguration config, Lookup lookup) {
		super(language);
		this.compiler = new JitCompiler(config);
		this.lookup = lookup;
	}

	@Override
	protected PcodeExecutorState<byte[]> createSharedState() {
		return new JitDefaultBytesPcodeExecutorState(language);
	}

	@Override
	protected PcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> thread) {
		return new JitDefaultBytesPcodeExecutorState(language);
	}

	@Override
	protected JitPcodeThread createThread(String name) {
		return new JitPcodeThread(name, this);
	}

	@Override
	public JitPcodeThread newThread() {
		return (JitPcodeThread) super.newThread();
	}

	@Override
	public JitPcodeThread newThread(String name) {
		return (JitPcodeThread) super.newThread(name);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Userops can be optimized by the JIT translator under certain circumstances. To read more, see
	 * {@link JitDataFlowUseropLibrary}. DO NOT extend that library. The internals use it to wrap
	 * the library you provide here, but its documentation describes when and how the JIT translator
	 * optimizes invocations to your userops.
	 * 
	 * <p>
	 * <b>WARNING</b>: Userops that accept floating point types via direct invocation should be
	 * careful that the sizes match exactly. That is, if you pass a {@code float} argument to a
	 * {@code double} parameter, you may have problems. This <em>does not</em> imply a conversion of
	 * floating point type. Instead, it will simply zero-fill the upper bits (as if zero-exending an
	 * integer) and reinterpret the resulting bits as a double. This is almost certainly
	 * <em>not</em> what you want. Until/unless we resolve this, the userop implementor must accept
	 * the proper types. It's possible multiple versions of the userop must be provided (overloading
	 * is not supported) to accept types of various sizes.
	 */
	@Override
	protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
		return super.createUseropLibrary();
	}

	/**
	 * Check if the emulator already has translated a given entry point.
	 * 
	 * <p>
	 * This is used by the decoder to detect if it should end a stride before reaching its natural
	 * end (i.e., a non-fall-through instruction.) This was a design decision to reduce
	 * re-translation of the same machine code. Terminating the stride will cause execution to exit
	 * the translated passage, but it will then immediately enter the existing translated passage.
	 * 
	 * @param pcCtx the program counter and contextreg value to check
	 * @return true if the emulator has a translation which can be entered at the given pcCtx.
	 */
	public boolean hasEntryPrototype(AddrCtx pcCtx) {
		/**
		 * TODO: Investigate ignoring synchronization and instead catching the CME. This would be to
		 * avoid locking on every instruction decode. If we thing there's no an entry, and there
		 * turns out we just won a race, it's little loss.
		 * 
		 * I don't think in the grand scheme of things, this is the most expensive operation of the
		 * translation. Nevertheless, it'll be hit a lot, so worth investigating.
		 */
		synchronized (codeCache) {
			CompletableFuture<EntryPointPrototype> proto = codeCache.get(pcCtx);
			return proto != null && proto.isDone();
		}
	}

	/**
	 * Translate a new passage starting at the given seed.
	 * 
	 * <p>
	 * Note the compiler must provide an entry to the resulting passage at the requested seed. It
	 * and any additional entry points are placed into the code cache. Each thread executing the
	 * passage must still create (and ought to cache) an instance of the translation.
	 * 
	 * @param pcCtx the seed address and contextreg value for decoding and selecting a passage
	 * @param decoder the passage decoder, provided by the thread
	 * @return the class that is the translation of the passage, and information about its entry
	 *         points.
	 */
	protected JitCompiledPassageClass compileWithMaxOpsBackoff(AddrCtx pcCtx,
			JitPassageDecoder decoder) {
		int maxOps = getConfiguration().maxPassageOps();
		while (maxOps > 0) {
			JitPassage decoded = decoder.decodePassage(pcCtx, maxOps);
			try {
				return compiler.compilePassage(lookup, decoded);
			}
			catch (MethodTooLargeException e) {
				Msg.warn(this, "Method too large for " + pcCtx + " with maxOps=" + maxOps +
					". Retrying with half.");
				maxOps >>= 1;
			}
		}
		/**
		 * This would be caused by an exceptionally large stride, perhaps with a good bit of
		 * instrumentation.
		 * 
		 * TODO: If this happens, we'll need to be willing to stop decoding mid-stride. I think it's
		 * easily doable, as we already do this when we hit an address with an existing entry point.
		 * 
		 * NOTE: We still need to treat each instruction, along with any instrumentation on it, as
		 * an atomic unit. I can't imagine a single instruction maxing out the Java method size,
		 * though.
		 */
		throw new AssertionError();
	}

	/**
	 * Get the entry prototype for a given address and contextreg value.
	 * 
	 * <p>
	 * An <b>entry prototype</b> is a class representing a translated passage and an index
	 * identifying the point at which to enter the passage. The compiler numbers each entry point it
	 * generates and provides those indices via a static field in the output class. Those entry
	 * point indices are entered into the code cache for each translated passage. If no entry point
	 * exists for the requested address and contextreg value, the emulator will decode and translate
	 * a new passage at the requested seed.
	 *
	 * <p>
	 * It's a bit odd to take the thread's decoder for a machine-level thing; however, all thread
	 * decoders ought to have the same behavior. The particular thread's decoder will have better
	 * cached instruction block state for decoding in the vicinity of its past execution, though.
	 * 
	 * @param pcCtx the counter and decoder context
	 * @param decoder the thread's decoder needing this entry point prototype
	 * @return the entry point prototype
	 * @see JitPcodeThread#getEntry(AddrCtx)
	 */
	public EntryPointPrototype getEntryPrototype(AddrCtx pcCtx, JitPassageDecoder decoder) {
		/**
		 * NOTE: It is possible for a race condition, still, if (very likely) the passage provides
		 * multiple entry points. It's not ideal, but still correct, I think, if this happens.
		 */
		CompletableFuture<EntryPointPrototype> proto;
		boolean wasAbsent;
		synchronized (codeCache) {
			proto = codeCache.get(pcCtx);
			wasAbsent = proto == null;
			if (wasAbsent) {
				proto = new CompletableFuture<>();
				codeCache.put(pcCtx, proto);
				// Won't know to put other entry points, yet
			}
		}
		/**
		 * TODO: I'm not sure it makes sense to do this computation without the lock.
		 * 
		 * On the one hand, it allows threads to avoid stalling on every translation, and instead
		 * only on translations for the same entry point. However, if we do keep the lock, then we
		 * can avoid the race condition on alternative entry points.
		 */

		if (wasAbsent) {
			/**
			 * Go ahead and use this thread instead of spawning another, because this one can't
			 * proceed until compilation is completed, anyway.
			 */
			try {
				JitCompiledPassageClass compiled = compileWithMaxOpsBackoff(pcCtx, decoder);
				synchronized (codeCache) {
					for (Entry<AddrCtx, EntryPointPrototype> ent : compiled.getBlockEntries()
							.entrySet()) {
						if (ent.getKey().equals(pcCtx)) {
							proto.complete(ent.getValue());
						}
						else {
							codeCache.put(ent.getKey(),
								CompletableFuture.completedFuture(ent.getValue()));
						}
					}
				}
			}
			catch (Throwable t) {
				proto.completeExceptionally(t);
			}
		}
		try {
			return proto.get();
		}
		catch (InterruptedException e) {
			throw new AssertionError(e);
		}
		catch (ExecutionException e) {
			return ExceptionUtils.rethrow(e);
		}
	}

	/**
	 * Get the configuration for this emulator.
	 * 
	 * @return the configuration
	 */
	public JitConfiguration getConfiguration() {
		return compiler.getConfiguration();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * <b>TODO</b>: The JIT-accelerated emulator does not currently implement access breakpoints.
	 * Furthermore, because JIT generated code is granted direct access to the emulator's state
	 * internals, it is not sufficient to override
	 * {@link PcodeExecutorStatePiece#getVar(AddressSpace, Object, int, boolean, Reason) getVar} and
	 * related.
	 */
	@Override
	public void addAccessBreakpoint(AddressRange range, AccessKind kind) {
		throw new UnsupportedOperationException();
	}
}
