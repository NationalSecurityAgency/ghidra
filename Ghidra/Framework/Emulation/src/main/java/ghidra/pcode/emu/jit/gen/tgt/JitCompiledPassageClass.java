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
package ghidra.pcode.emu.jit.gen.tgt;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.invoke.MethodType;
import java.util.*;

import ghidra.pcode.emu.jit.*;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPointPrototype;

/**
 * A compiled passage that is not yet bound/instantiated to a thread.
 * 
 * <p>
 * This is the output of {@link JitCompiler#compilePassage(Lookup, JitPassage)}, and it will be
 * cached (indirectly) by {@link JitPcodeEmulator}. The emulator actually caches the various entry
 * points returned by {@link #getBlockEntries()}. Each of those retains a reference to this object.
 * An {@link EntryPointPrototype} pairs this with a entry block ID. That prototype can then be
 * instantiated/bound to a thread, producing an {@link EntryPoint}. That bound entry point is
 * produced by invoking {@link #createInstance(JitPcodeThread)} and just copying the block id.
 * 
 * <p>
 * This object wraps the generated (and now loaded) class and provides the mechanisms for reflecting
 * and processing the {@code ENTRIES} field, and for reflecting and invoking the generated
 * constructor. Note that explicit invocation of the static initializer via reflection is not
 * necessary.
 * 
 * @param lookup the means of accessing the generated class's elements
 * @param cls the generated class as loaded into this JVM
 * @param constructor the reflected constructor having signature {@link #CONSTRUCTOR_TYPE}
 */
public record JitCompiledPassageClass(Lookup lookup, Class<? extends JitCompiledPassage> cls,
		MethodHandle constructor) {

	/**
	 * The constructor signature: {@code Passage$at_[entry](JitPcodeThread)}
	 */
	public static final MethodType CONSTRUCTOR_TYPE =
		MethodType.methodType(void.class, JitPcodeThread.class);

	/**
	 * Load the generated class from the given bytes
	 * 
	 * <p>
	 * The bytes must define a class that implements {@link JitCompiledPassage}. It must define a
	 * constructor having the signature {@link #CONSTRUCTOR_TYPE}, and it must define a static field
	 * {@code List<AddrCtx> ENTRIES}.
	 * 
	 * @param lookup a lookup that can see all the elements the generated class needs. Likely, this
	 *            should be from the emulator implementation, which may be an extension in a script.
	 * @param bytes the classfile bytes
	 * @return the wrapped class
	 */
	public static JitCompiledPassageClass load(Lookup lookup, byte[] bytes) {
		try {
			Lookup defLookup = lookup.defineHiddenClass(bytes, true);
			@SuppressWarnings("unchecked")
			Class<? extends JitCompiledPassage> cls =
				(Class<? extends JitCompiledPassage>) defLookup.lookupClass();
			MethodHandle constructor = defLookup.findConstructor(cls, CONSTRUCTOR_TYPE);
			return new JitCompiledPassageClass(defLookup, cls, constructor);
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Create an instance bound to the given thread
	 * 
	 * @param thread the thread
	 * @return the instance, prepared to execute on the given thread
	 */
	public JitCompiledPassage createInstance(JitPcodeThread thread) {
		try {
			return (JitCompiledPassage) constructor.invoke(thread);
		}
		catch (Throwable e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Get the entry points for this compiled passage
	 * 
	 * <p>
	 * This processes the {@code ENTRIES} field, which is just a list of targets. The position of
	 * each target in the list corresponds to the block id accepted by the generated
	 * {@link JitCompiledPassage#run(int)} method.
	 * 
	 * @return the map of targets to their corresponding entry point prototypes
	 */
	public Map<AddrCtx, EntryPointPrototype> getBlockEntries() {
		try {
			MethodHandle getter = lookup.findStaticGetter(cls, "ENTRIES", List.class);
			List<AddrCtx> entries = (List<AddrCtx>) getter.invoke();
			Map<AddrCtx, EntryPointPrototype> result = new HashMap<>();
			for (int i = 0; i < entries.size(); i++) {
				result.put(entries.get(i), new EntryPointPrototype(this, i));
			}
			return result;
		}
		catch (Throwable e) {
			throw new AssertionError(e);
		}
	}
}
