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
import java.nio.charset.Charset;
import java.util.List;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.struct.StructuredSleigh;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.pcode.Varnode;

/**
 * A userop library for the emulator
 * 
 * <p>
 * If you do not need a custom userop library, use {@link PcodeUseropLibrary#NIL}. These libraries
 * allow you to implement userops, including those declared by the language. Without these, the
 * emulator must interrupt whenever a userop ({@code CALLOTHER}) is encountered. You can also define
 * new userops, which can be invoked from Sleigh code injected into the emulator.
 * 
 * <p>
 * These libraries can have both Java-callback and p-code implementations of userops. If only using
 * p-code implementations, the library can be parameterized with type {@code <T>} and just pass that
 * over to {@link AnnotatedPcodeUseropLibrary}. Because this will demo a Java callback that assumes
 * concrete bytes, we will fix the library's type to {@code byte[]}. With careful use of the
 * {@link PcodeArithmetic}, you can keep the type an abstract {@code <T>} with Java callbacks.
 * 
 * <p>
 * Methods in this class (not including those in its nested classes) are implemented as Java
 * callbacks.
 */
public class DemoPcodeUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {
	private final static Charset UTF8 = Charset.forName("utf8");

	private final SleighLanguage language;
	private final GhidraScript script;
	private final AddressSpace space;

	public DemoPcodeUseropLibrary(SleighLanguage language, GhidraScript script) {
		this.language = language;
		this.script = script;
		this.space = language.getDefaultSpace();

		new DemoStructuredPart(language.getDefaultCompilerSpec()).generate(ops);
	}

	/**
	 * Treats the input as an offset to a C-style string and prints it to the console
	 * 
	 * <p>
	 * Because we want to dereference start, we will need access to the emulator's state, so we
	 * employ the {@link OpState} annotation. {@code start} takes the one input we expect. Because
	 * its type is the value type rather than {@link Varnode}, we will get the input's value.
	 * Similarly, we can just return the resulting value, and the emulator will place that into the
	 * output variable for us.
	 * 
	 * @param state the calling thread's state
	 * @param start the offset of the first character
	 * @return the length of the string in bytes
	 */
	@PcodeUserop
	public byte[] print_utf8(@OpExecutor PcodeExecutor<byte[]> executor, byte[] start) {
		PcodeExecutorState<byte[]> state = executor.getState();
		long offset = Utils.bytesToLong(start, start.length, language.isBigEndian());
		long end = offset;
		Reason reason = executor.getReason();
		while (state.getVar(space, end, 1, true, reason)[0] != 0) {
			end++;
		}
		if (end == offset) {
			script.println("");
			return Utils.longToBytes(0, Long.BYTES, language.isBigEndian());
		}
		byte[] bytes = state.getVar(space, offset, (int) (end - offset), true, reason);
		String str = new String(bytes, UTF8);
		script.println(str);
		return Utils.longToBytes(end - offset, Long.BYTES, language.isBigEndian());
	}

	/**
	 * Methods in this class are implemented using p-code compiled from Structured Sleigh
	 */
	public class DemoStructuredPart extends StructuredSleigh {
		final Var RAX = lang("RAX", type("long"));
		final Var RCX = lang("RCX", type("byte *"));
		final UseropDecl emu_swi = userop(type("void"), "emu_swi", List.of());

		protected DemoStructuredPart(CompilerSpec cs) {
			super(cs);
		}

		/**
		 * Not really a syscall dispatcher
		 * 
		 * <p>
		 * In cases where the userop expects parameters, you would annotate them with {@link Param}
		 * and use them just like other {@link Var}s. See the javadocs.
		 * 
		 * <p>
		 * This is just a cheesy demo: If RAX is 1, then this method computes the number of bytes in
		 * the C-style string pointed to by RCX and stores the result in RAX. Otherwise, interrupt
		 * the emulator. See {@link DemoSyscallLibrary} for actual system call simulation.
		 */
		@StructuredUserop
		public void syscall() {
			_if(RAX.eq(1), () -> {
				Var i = local("i", RCX);
				_while(i.deref().neq(0), () -> {
					i.inc();
				});
				RAX.set(i.subi(RAX));
			})._else(() -> {
				emu_swi.call();
			});
		}
	}
}
