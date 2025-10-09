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
package ghidra.pcode.emu;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;

/**
 * A p-code machine which executes on concrete bytes and incorporates per-architecture state
 * modifiers
 * 
 * <p>
 * This is a simple concrete bytes emulator suitable for unit testing and scripting. More complex
 * use cases likely benefit by extending this or one of its super types. Likewise, the factory
 * methods will likely instantiate classes which extend the default or one of its super types. When
 * creating such an extension, it helps to refer to this default implementation to understand the
 * overall architecture of an emulator. The emulator was designed using hierarchies of abstract
 * classes each extension incorporating more complexity (and restrictions) finally culminating here.
 * Every class should be extensible and have overridable factory methods so that those extensions
 * can be incorporated into even more capable emulators. Furthermore, many components, e.g.,
 * {@link PcodeExecutorState} were designed with composition in mind. Referring to examples, it is
 * straightforward to extend the emulator via composition. Consider using {@link AuxPcodeEmulator}
 * or one of its derivatives to create a concrete-plus-auxiliary style emulator.
 * 
 * <p>
 * Note that extending the emulator and integrating with emulation use two different patterns.
 * Extending the emulator generally means advancing its core behavior in some way, e.g., replacing
 * its execution engine or adapting it to a new domain. For such cases, extend this class or
 * {@link AbstractPcodeMachine} or similar. Integrating with an emulator means reacting to events,
 * tweaking initialization, serializing state, etc. For such cases, implement
 * {@link PcodeEmulationCallbacks} and pass it into the emulator's constructor. In general, favor
 * the callbacks mechanism, as this is more easily composed with other integrations. By their
 * nature, and due to restrictions on inheritance in Java, different extensions cannot be easily
 * composed. Though encouraged, it is possible an extended emulator does not accept/issue callbacks.
 * Read its documentation to learn which, if any, of the callbacks are actually supported. The base
 * {@link PcodeEmulator} supports all the callbacks in {@link PcodeEmulationCallbacks}.
 * 
 * <pre>
 * emulator      : {@link PcodeMachine}{@code <T>}
 *  - language     : {@link SleighLanguage}
 *  - arithmetic   : {@link PcodeArithmetic}{@code <T>}
 *  - sharedState  : {@link PcodeExecutorState}{@code <T>}
 *  - library      : {@link PcodeUseropLibrary}{@code <T>}
 *  - injects      : {@code Map<Address, }{@link PcodeProgram}{@code >}
 *  - threads      : {@code List<}{@link PcodeThread}{@code <T>>}
 *    - [0]          : {@link PcodeThread}{@code <T>}
 *      - decoder      : {@link InstructionDecoder}
 *      - executor     : {@link PcodeExecutor}{@code <T>}
 *      - frame        : {@link PcodeFrame}
 *      - localState   : {@link PcodeExecutorState}{@code <T>}
 *      - library      : {@link PcodeUseropLibrary}{@code <T>}
 *      - injects      : {@code Map<Address, }{@link PcodeProgram}{@code >}
 *    - [1] ...
 * </pre>
 * 
 * <p>
 * The root object of an emulator is the {@link PcodeEmulator}, usually ascribed the type
 * {@link PcodeMachine}. At the very least, it must know the language of the processor it emulates.
 * It then derives appropriate arithmetic definitions, a shared (memory) state, and a shared userop
 * library. Initially, the machine has no threads. For many use cases creating a single
 * {@link PcodeThread} suffices; however, this default implementation models multi-threaded
 * execution "out of the box." Upon creation, each thread is assigned a local (register) state, and
 * a userop library for controlling that particular thread. The thread's full state and userop
 * library are composed from the machine's shared components and that thread's particular
 * components. For state, the composition directs memory accesses to the machine's state and
 * register accesses to the thread's state. (Accesses to the "unique" space are also directed to the
 * thread's state.) This properly emulates the thread semantics of most platforms. For the userop
 * library, composition is achieved via {@link PcodeUseropLibrary#compose(PcodeUseropLibrary)}.
 * Thus, each invocation is directed to the library that exports the invoked userop.
 * 
 * <p>
 * Each thread creates an {@link InstructionDecoder} and a {@link PcodeExecutor}, providing the
 * kernel of p-code emulation for that thread. That executor is bound to the thread's composed
 * state, and to the machine's arithmetic. Together, the state and the arithmetic "define" all the
 * p-code ops that the executor can invoke. Unsurprisingly, arithmetic operations are delegated to
 * the {@link PcodeArithmetic}, and state operations (including memory operations and temporary
 * variable access) are delegated to the {@link PcodeExecutorState}. The core execution loop easily
 * follows: 1) decode the current instruction, 2) generate that instruction's p-code, 3) feed the
 * code to the executor, 4) resolve the outcome and advance the program counter, then 5) repeat. So
 * long as the arithmetic and state objects agree in type, a p-code machine can be readily
 * implemented to manipulate values of that type.
 * 
 * <p>
 * This concrete emulator chooses a {@link BytesPcodeArithmetic} based on the endianness of the
 * target language. Its threads are {@link BytesPcodeThread}. The shared and thread-local states are
 * all {@link BytesPcodeExecutorState}. Callbacks may be provided to read through to some other
 * backing object. For example, the memory state could read through to an imported program image,
 * which allows the emulator's memory to be loaded lazily.
 * 
 * <p>
 * The default userop library is empty. For many use cases, it will be necessary to override
 * {@link #createUseropLibrary()} if only to implement the language-defined userops. If needed,
 * simulation of the host operating system is typically achieved by implementing the {@code syscall}
 * userop. The fidelity of that simulation depends on the use case. See the SystemEmulation module
 * to see what simulators are available "out of the box."
 * 
 * <p>
 * Alternatively, if the target program never invokes system calls directly, but rather via
 * system-provided APIs, then it may suffice to stub out those imports. Typically, Ghidra will place
 * a "thunk" at each import address with the name of the import. Stubbing an import is accomplished
 * by injecting p-code at the import address. See {@link PcodeMachine#inject(Address, String)}. The
 * inject will need to replicate the semantics of that call to the desired fidelity.
 * <b>IMPORTANT:</b> The inject must also return control to the calling function, usually by
 * replicating the conventions of the target platform. See the Debugger course for more information.
 */
public class PcodeEmulator extends AbstractPcodeMachine<byte[]> {
	/**
	 * Construct a new concrete emulator
	 * 
	 * <p>
	 * Yes, it is customary to invoke this constructor directly.
	 * 
	 * @param language the language of the target processor
	 * @param cb callbacks to receive emulation events
	 */
	public PcodeEmulator(Language language, PcodeEmulationCallbacks<byte[]> cb) {
		super(language, cb);
	}

	/**
	 * Construct a new concrete emulator
	 * 
	 * <p>
	 * Yes, it is customary to invoke this constructor directly.
	 * 
	 * @param language the language of the target processor
	 */
	public PcodeEmulator(Language language) {
		this(language, PcodeEmulationCallbacks.none());
	}

	@Override
	protected PcodeArithmetic<byte[]> createArithmetic() {
		return BytesPcodeArithmetic.forLanguage(language);
	}

	@Override
	protected BytesPcodeThread createThread(String name) {
		return new BytesPcodeThread(name, this);
	}

	@Override
	protected PcodeExecutorState<byte[]> createSharedState() {
		PcodeStateCallbacks scb = cb.wrapFor(null);
		return new BytesPcodeExecutorState(language, scb);
	}

	@Override
	protected PcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> thread) {
		PcodeStateCallbacks scb = cb.wrapFor(thread);
		return new BytesPcodeExecutorState(language, scb);
	}

	@Override
	protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
		return PcodeUseropLibrary.nil();
	}
}
