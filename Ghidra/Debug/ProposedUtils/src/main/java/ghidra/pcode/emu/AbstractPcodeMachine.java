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

import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.util.classfinder.ClassSearcher;

/**
 * An abstract implementation of {@link PcodeMachine} suitable as a base for most implementations
 */
public abstract class AbstractPcodeMachine<T> implements PcodeMachine<T> {
	protected final SleighLanguage language;
	protected final PcodeArithmetic<T> arithmetic;
	protected final SleighUseropLibrary<T> library;

	protected final SleighUseropLibrary<T> stubLibrary;

	/* for abstract thread access */ PcodeStateInitializer initializer;
	private PcodeExecutorState<T> sharedState;
	protected final Map<String, PcodeThread<T>> threads = new LinkedHashMap<>();
	protected final Collection<PcodeThread<T>> threadsView =
		Collections.unmodifiableCollection(threads.values());

	protected final Map<Address, PcodeProgram> injects = new HashMap<>();

	public AbstractPcodeMachine(SleighLanguage language, PcodeArithmetic<T> arithmetic,
			SleighUseropLibrary<T> library) {
		this.language = language;
		this.arithmetic = arithmetic;
		this.library = library;

		this.stubLibrary = createThreadStubLibrary().compose(library);

		/**
		 * NOTE: Do not initialize memoryState here, since createMemoryState may depend on fields
		 * initialized in a sub-constructor
		 */

		this.initializer = getPluggableInitializer(language);
	}

	@Override
	public SleighLanguage getLanguage() {
		return language;
	}

	@Override
	public PcodeArithmetic<T> getArithmetic() {
		return arithmetic;
	}

	@Override
	public SleighUseropLibrary<T> getUseropLibrary() {
		return library;
	}

	@Override
	public SleighUseropLibrary<T> getStubUseropLibrary() {
		return stubLibrary;
	}

	protected abstract PcodeExecutorState<T> createSharedState();

	protected abstract PcodeExecutorState<T> createLocalState(PcodeThread<T> thread);

	protected SleighUseropLibrary<T> createThreadStubLibrary() {
		return new DefaultPcodeThread.SleighEmulationLibrary<T>(null);
	}

	/**
	 * Extension point to override construction of this machine's threads
	 * 
	 * @param name the name of the new thread
	 * @return the new thread
	 */
	protected PcodeThread<T> createThread(String name) {
		return new DefaultPcodeThread<>(name, this);
	}

	protected static PcodeStateInitializer getPluggableInitializer(Language language) {
		for (PcodeStateInitializer init : ClassSearcher.getInstances(PcodeStateInitializer.class)) {
			if (init.isApplicable(language)) {
				return init;
			}
		}
		return null;
	}

	protected void doPluggableInitialization() {
		if (initializer != null) {
			initializer.initializeMachine(this);
		}
	}

	@Override
	public PcodeThread<T> newThread() {
		return newThread("Thread " + threads.size());
	}

	@Override
	public PcodeThread<T> newThread(String name) {
		if (threads.containsKey(name)) {
			throw new IllegalStateException("Thread with name '" + name + "' already exists");
		}
		PcodeThread<T> thread = createThread(name);
		threads.put(name, thread);
		return thread;
	}

	@Override
	public PcodeThread<T> getThread(String name, boolean createIfAbsent) {
		PcodeThread<T> thread = threads.get(name);
		if (thread == null && createIfAbsent) {
			thread = newThread(name);
		}
		return thread;
	}

	@Override
	public Collection<? extends PcodeThread<T>> getAllThreads() {
		return threadsView;
	}

	@Override
	public PcodeExecutorState<T> getSharedState() {
		if (sharedState == null) {
			sharedState = createSharedState();
			doPluggableInitialization();
		}
		return sharedState;
	}

	protected PcodeProgram getInject(Address address) {
		return injects.get(address);
	}

	@Override
	public PcodeProgram compileSleigh(String sourceName, List<String> lines) {
		return SleighProgramCompiler.compileProgram(language, sourceName, lines, stubLibrary);
	}

	@Override
	public void inject(Address address, List<String> sleigh) {
		/**
		 * TODO: Can I compile the template and build as if the inject were a
		 * instruction:^instruction constructor? This would require me to delay that build until
		 * execution, or at least check for instruction modification, if I do want to cache the
		 * built p-code.
		 */
		PcodeProgram pcode = compileSleigh("machine_inject:" + address, sleigh);
		injects.put(address, pcode);
	}

	@Override
	public void clearInject(Address address) {
		injects.remove(address);
	}

	@Override
	public void clearAllInjects() {
		injects.clear();
	}

	@Override
	public void addBreakpoint(Address address, String sleighCondition) {
		/**
		 * TODO: The template build idea is probably more pertinent here. If a user places a
		 * breakpoint with the purpose of single-stepping the p-code of that instruction, it won't
		 * work, because that p-code is occluded by emu_exec_decoded().
		 */
		PcodeProgram pcode = compileSleigh("breakpoint:" + address, List.of(
			"if (!(" + sleighCondition + ")) goto <nobreak>;",
			"    emu_swi();",
			"<nobreak>",
			"    emu_exec_decoded();"));
		injects.put(address, pcode);
	}
}
