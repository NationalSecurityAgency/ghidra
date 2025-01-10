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

import java.util.HashMap;
import java.util.Map;

import ghidra.lifecycle.Internal;
import ghidra.pcode.emu.*;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.decode.JitPassageDecoder;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPointPrototype;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.ProgramContext;

/**
 * A JIT-accelerated thread of p-code emulation
 * 
 * <p>
 * This class implements the actual JIT-accelerated execution loop. In contrast to the normal
 * per-instruction Fetch-Execute-Store loop inherited from {@link DefaultPcodeThread}, this thread's
 * {@link #run()} method implements a per-<em>passage</em> Fetch-Decode-Translate-Execute loop.
 * 
 * 
 * <h2>Fetch</h2>
 * <p>
 * The Fetch step involves checking the code cache for an existing translation at the thread's
 * current counter and decode context. Cache entries are keyed by <em>passage entry point</em>, that
 * is an address (and context reg value, if applicable) within a passage where execution is
 * permitted to enter. This typically consists of the passage's seed as well as each branch target
 * in the same passage. If one is found, we skip the Decode and Translate steps, and proceed
 * directly to Execute.
 * 
 * <h2>Decode</h2>
 * <p>
 * The Decode step involves decoding and selecting several instructions into a <em>passage</em>. A
 * passage may comprise of several instructions connected by control flow. Often it is a few long
 * strides of instructions connected by a few branches. The decoder will avoid selecting
 * instructions that are already included in an existing translated passage. The reason for this
 * complexity is that JVM bytecode cannot be rewritten or patched once loaded. For more details, see
 * {@link JitPassageDecoder}.
 * 
 * <h2>Translate</h2>
 * <p>
 * The Translate step involves translating the selected passage of instructions. The result of this
 * translation implements {@link JitCompiledPassage}. For details of this translation process, see
 * {@link JitCompiler}. The compiled passage provides a list of its entry points. Each is added to
 * the emulator's code cache. Among those should be the seed required by this iteration of the
 * execution loop, and so that entry point is chosen.
 * 
 * <h2>Execute</h2>
 * <p>
 * The chosen entry point is then executed. This step is as simple as invoking the
 * {@link EntryPoint#run()} method. This, in turn, invokes {@link JitCompiledPassage#run(int)},
 * providing the entry point's index as an argument. The index identifies to the translated passage
 * the desired address of entry, and so it jumps directly to the corresponding translation. That
 * translation performs all the equivalent operations of the selected instructions, adhering to any
 * control flow within. When control flow exits the passage, the method returns, and the loop
 * repeats.
 */
public class JitPcodeThread extends BytesPcodeThread {
	/**
	 * This thread's passage decoder, which is based on its {@link #getDecoder() instruction
	 * decoder}.
	 */
	protected final JitPassageDecoder passageDecoder;

	/**
	 * This thread's cache of translations instantiated for this thread.
	 * 
	 * <p>
	 * As an optimization, the translator generates classes which pre-fetch portions of the thread's
	 * state. Thus, the class must be instantiated for each particular thread needing to execute it.
	 * 
	 * <p>
	 * TODO: Invalidation of entries. There are several reasons an entry may need to be invalidated:
	 * Expiration, eviction, or perhaps because the {@link EntryPointPrototype} (from the emulator)
	 * was invalidated.
	 */
	protected final Map<AddrCtx, EntryPoint> codeCache = new HashMap<>();

	/**
	 * Create a thread
	 * 
	 * <p>
	 * This should only be called by the emulator and its test suites.
	 * 
	 * @param name the name of the thread
	 * @param machine the machine creating the thread
	 */
	public JitPcodeThread(String name, JitPcodeEmulator machine) {
		super(name, machine);
		this.passageDecoder = createPassageDecoder();
	}

	@Override
	protected ThreadPcodeExecutorState<byte[]> createThreadState(
			PcodeExecutorState<byte[]> sharedState, PcodeExecutorState<byte[]> localState) {
		return new JitThreadBytesPcodeExecutorState((JitDefaultBytesPcodeExecutorState) sharedState,
			(JitDefaultBytesPcodeExecutorState) localState);
	}

	/**
	 * Create the passage decoder
	 * 
	 * <p>
	 * This is an extension point in case the decoder needs to be replaced with a further extension.
	 * 
	 * @return the new passage decoder
	 */
	protected JitPassageDecoder createPassageDecoder() {
		return new JitPassageDecoder(this);
	}

	@Override
	public JitPcodeEmulator getMachine() {
		return (JitPcodeEmulator) super.getMachine();
	}

	@Override
	public JitThreadBytesPcodeExecutorState getState() {
		return (JitThreadBytesPcodeExecutorState) super.getState();
	}

	@Internal
	@Override
	public PcodeProgram getInject(Address address) {
		return super.getInject(address);
	}

	/**
	 * An accessor so the passage decoder can retrieve its thread's instruction decoder.
	 * 
	 * @return the decoder
	 */
	@Internal
	public InstructionDecoder getDecoder() {
		return decoder;
	}

	/**
	 * An accessor so the passage decoder can query the language's default program context.
	 * 
	 * @return the context
	 */
	@Internal
	public ProgramContext getDefaultContext() {
		return defaultContext;
	}

	@Override
	public void inject(Address address, String source) {
		/**
		 * TODO: Flush code cache? Alternatively, establish some convention where injects cannot be
		 * changed in the life cycle? I don't like that solution. It is workable, I think, though,
		 * but the user would have to add state to a library in order to configure/toggle each
		 * injection.
		 * 
		 * Is it enough to identify which passages contain the address and just remove those? I
		 * think, so. The only nuance I can think of is that the inject may change the block
		 * structure, i.e., new entries are possible, but I don't think that matters terribly. The
		 * caching algorithm should work that out.
		 */
		super.inject(address, source);
	}

	/**
	 * Check if the <em>emulator</em> has an entry prototype for the given address and contextreg
	 * value.
	 * 
	 * <p>
	 * This simply passes through to the emulator. It does not matter whether or not this thread has
	 * instantiated the prototype or not. If any thread has caused the emulator to translate the
	 * given entry, this will return true.
	 * 
	 * @see JitPcodeEmulator#hasEntryPrototype(AddrCtx)
	 * @param pcCtx the address and contextreg to check
	 * @return true if the emulator has a translation which can be entered at the given pcCtx.
	 */
	public boolean hasEntry(AddrCtx pcCtx) {
		return getMachine().hasEntryPrototype(pcCtx);
	}

	/**
	 * Get the translated and instantiated entry point for the given address and contextreg value.
	 * 
	 * <p>
	 * An <b>entry point</b> is an instance of a class representing a translated passage and an
	 * index identifying the point at which to enter the passage. In essence, it is an instance of
	 * an <b>entry prototype</b> for this thread.
	 * 
	 * <p>
	 * This will first check the cache for an existing instance. Then, it will delegate to the
	 * emulator. The emulator will check its cache for an existing translation. If one is found, we
	 * simply take it and instantiate it for this thread. Otherwise, the emulator translates a new
	 * passage at the given seed, and we instantiate it for this thread.
	 * 
	 * @see JitPcodeEmulator#getEntryPrototype(AddrCtx, JitPassageDecoder)
	 * @param pcCtx the counter and decoder context
	 * @return the entry point
	 */
	public EntryPoint getEntry(AddrCtx pcCtx) {
		/**
		 * NOTE: Placeholders are not needed at the thread level, but at the machine level.
		 */
		return codeCache.computeIfAbsent(pcCtx,
			k -> getMachine().getEntryPrototype(k, passageDecoder).createInstance(this));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We override only this method to accelerate execution using JIT translation. Implementing
	 * single stepping via JIT doesn't make much sense from an efficiency standpoint. However, this
	 * thread still supports stepping via interpretation (as inherited). Our implementation permits
	 * mixing the two execution paradigms; however, using JIT after a few single steps will incur
	 * some waste as the JIT translates an otherwise uncommon entry point. Depending on
	 * circumstances and the order of operations, the effect of this on overall efficiency may vary
	 * because of caching.
	 */
	@Override
	public void run() {
		setSuspended(false);
		if (frame != null) {
			finishInstruction();
		}
		EntryPoint next = null;
		while (!isSuspended()) {
			if (next == null) {
				next = getEntry(new AddrCtx(getContext(), getCounter()));
			}
			try {
				next = next.run();
			}
			catch (SuspendedPcodeExecutionException e) {
				// Cool.
			}
		}
	}

	/**
	 * This is called before each basic block is executed.
	 * 
	 * <p>
	 * This gives the thread an opportunity to track and control execution, if desired. It provides
	 * the number of instructions and additional p-code ops about to be completed. If the counts
	 * exceed a desired schedule, or if the thread is suspended, this method may throw an exception
	 * to interrupt execution. This can be toggled in the emulator's configuration.
	 * 
	 * @see JitConfiguration#emitCounters()
	 * @param instructions the number of instruction about to be completed
	 * @param trailingOps the number of ops of a final partial instruction about to be completed. If
	 *            the block does not complete any instruction, this is the number of ops continuing
	 *            in the current (partial) instruction.
	 */
	public void count(int instructions, int trailingOps) {
		if (isSuspended()) {
			throw new SuspendedPcodeExecutionException(null, null);
		}
	}
}
