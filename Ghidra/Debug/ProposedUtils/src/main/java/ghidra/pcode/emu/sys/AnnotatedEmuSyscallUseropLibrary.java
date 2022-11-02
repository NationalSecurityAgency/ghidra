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
package ghidra.pcode.emu.sys;

import java.lang.annotation.*;
import java.lang.reflect.Method;
import java.util.*;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.struct.StructuredSleigh;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import utilities.util.AnnotationUtilities;

/**
 * A syscall library wherein Java methods are exported via a special annotated
 * 
 * <p>
 * This library is both a system call and a sleigh userop library. To export a system call, it must
 * also be exported as a sleigh userop. This is more conventional, as the system call dispatcher
 * does not require it, however, this library uses a wrapping technique that does require it. In
 * general, exporting system calls as userops will make developers and users lives easier. To avoid
 * naming collisions, system calls can be exported with customized names.
 * 
 * @param <T> the type of data processed by the library, typically {@code byte[]}
 */
public abstract class AnnotatedEmuSyscallUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T>
		implements EmuSyscallLibrary<T> {
	public static final String SYSCALL_SPACE_NAME = "syscall";

	protected static final Map<Class<?>, Set<Method>> CACHE_BY_CLASS = new HashMap<>();

	private static Set<Method> collectSyscalls(Class<?> cls) {
		return AnnotationUtilities.collectAnnotatedMethods(EmuSyscall.class, cls);
	}

	/**
	 * An annotation to export a method as a system call in the library.
	 * 
	 * <p>
	 * The method must also be exported in the userop library, likely via {@link PcodeUserop}.
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.METHOD)
	public @interface EmuSyscall {
		String value();
	}

	private final SyscallPcodeUseropDefinition<T> syscallUserop =
		new SyscallPcodeUseropDefinition<>(this);

	protected final PcodeMachine<T> machine;
	protected final CompilerSpec cSpec;

	protected final Program program;
	protected final DataType dtMachineWord;
	protected final Map<Long, EmuSyscallDefinition<T>> syscallMap = new HashMap<>();

	protected final Collection<DataTypeManager> additionalArchives;

	/**
	 * Construct a new library including the "syscall" userop
	 * 
	 * @param machine the machine using this library
	 * @param program a program from which to derive syscall configuration, conventions, etc.
	 */
	public AnnotatedEmuSyscallUseropLibrary(PcodeMachine<T> machine, Program program) {
		this.machine = machine;
		this.program = program;

		this.cSpec = program.getCompilerSpec();
		// TODO: Take signatures / types from database
		this.dtMachineWord = UseropEmuSyscallDefinition.requirePointerDataType(program);
		mapAndBindSyscalls();

		additionalArchives = getAdditionalArchives();
		StructuredSleigh structured = newStructuredPart();
		structured.generate(ops);
		disposeAdditionalArchives();
		mapAndBindSyscalls(structured.getClass());
	}

	protected Collection<DataTypeManager> getAdditionalArchives() {
		return List.of();
	}

	protected void disposeAdditionalArchives() {
	}

	/**
	 * Create the structured-sleigh part of this library
	 * 
	 * @return the structured part
	 */
	protected StructuredPart newStructuredPart() {
		return new StructuredPart();
	}

	/**
	 * Export a userop as a system call
	 * 
	 * @param opdef the userop
	 * @return the syscall definition
	 */
	public UseropEmuSyscallDefinition<T> newBoundSyscall(PcodeUseropDefinition<T> opdef,
			PrototypeModel convention) {
		return new UseropEmuSyscallDefinition<>(opdef, program, convention, dtMachineWord);
	}

	protected void mapAndBindSyscalls(Class<?> cls) {
		BidiMap<Long, String> mapNames =
			new DualHashBidiMap<>(EmuSyscallLibrary.loadSyscallNumberMap(program));
		Map<Long, PrototypeModel> mapConventions =
			EmuSyscallLibrary.loadSyscallConventionMap(program);
		Set<Method> methods = collectSyscalls(cls);
		for (Method m : methods) {
			String name = m.getAnnotation(EmuSyscall.class).value();
			Long number = mapNames.getKey(name);
			if (number == null) {
				Msg.warn(cls, "Syscall " + name + " has no number");
				continue;
			}
			PcodeUseropDefinition<T> opdef = getUserops().get(m.getName());
			if (opdef == null) {
				throw new IllegalArgumentException("Method " + m.getName() +
					" annotated with @" + EmuSyscall.class.getSimpleName() +
					" must also be a p-code userop");
			}
			PrototypeModel convention = mapConventions.get(number);
			EmuSyscallDefinition<T> existed =
				syscallMap.put(number, newBoundSyscall(opdef, convention));
			if (existed != null) {
				throw new IllegalArgumentException("Duplicate @" +
					EmuSyscall.class.getSimpleName() + " annotated methods with name " + name);
			}
		}
	}

	protected void mapAndBindSyscalls() {
		mapAndBindSyscalls(this.getClass());
	}

	@Override
	public PcodeUseropDefinition<T> getSyscallUserop() {
		return syscallUserop;
	}

	@Override
	public Map<Long, EmuSyscallDefinition<T>> getSyscalls() {
		return syscallMap;
	}

	protected class StructuredPart extends StructuredSleigh {
		protected StructuredPart() {
			super(program);
			addDataTypeSources(additionalArchives);
		}
	}
}
