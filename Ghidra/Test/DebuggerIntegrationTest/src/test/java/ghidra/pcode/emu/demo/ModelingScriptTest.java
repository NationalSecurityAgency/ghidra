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
package ghidra.pcode.emu.demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.invoke.MethodType;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyBuffer;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.jit.*;
import ghidra.pcode.exec.DecodePcodeExecutionException;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;

public class ModelingScriptTest extends AbstractGenericTest {
	static final LanguageID LANGID_X86_64 = new LanguageID("x86:LE:64:default");

	Language language;

	@Before
	public void setUp() throws Exception {
		language = DefaultLanguageService.getLanguageService().getLanguage(LANGID_X86_64);
	}

	protected void runTestOnEmulator(PcodeEmulator emu) throws Exception {
		Address entry = language.getDefaultSpace().getAddress(0x00400000);
		Address addrHw = language.getDefaultDataSpace().getAddress(0x00600000);
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(language), entry);
		asm.assemble("MOV RDI, 0x%x".formatted(addrHw.getOffset()));
		asm.assemble("MOV RSI, 100");
		Address call = asm.getNext();
		asm.assemble("CALL 0");
		asm.assemble("RET");
		Address extStrnlen = asm.getNext();
		asm.assemble("NOP");
		// Back patches
		asm.assemble(call, "CALL 0x%x".formatted(extStrnlen.getOffset()));

		byte[] codeBytes = asm.getBytes();
		emu.getSharedState().setVar(entry, codeBytes.length, false, codeBytes);
		byte[] hwBytes = "Hello, World!\n\0".getBytes();
		emu.getSharedState().setVar(addrHw, hwBytes.length, false, hwBytes);

		PcodeThread<byte[]> thread = emu.newThread();
		thread.setCounter(entry);
		thread.overrideContextWithDefault();
		thread.inject(extStrnlen, """
				__libc_strnlen();
				RIP = __x86_64_POP();
				return [RIP];
				""");

		try {
			thread.run();
		}
		catch (DecodePcodeExecutionException e) {
			assertEquals(0, e.getProgramCounter().getOffset());
		}
		Register regRAX = language.getRegister("RAX");
		assertEquals(14,
			thread.getState().inspectRegisterValue(regRAX).getUnsignedValue().longValueExact());
	}

	<T> PcodeUseropLibrary<T> reflect(String name) {
		Lookup lookup = MethodHandles.lookup();
		try {
			return (PcodeUseropLibrary<T>) lookup
					.findConstructor(lookup.findClass(name),
						MethodType.methodType(void.class))
					.invoke();
		}
		catch (Throwable e) {
			throw new AssertionError(e);
		}
	}

	<T> PcodeUseropLibrary<T> reflect(String name, Language language) {
		Lookup lookup = MethodHandles.lookup();
		try {
			return (PcodeUseropLibrary<T>) lookup
					.findConstructor(lookup.findClass(name),
						MethodType.methodType(void.class, Language.class))
					.invoke(language);
		}
		catch (Throwable e) {
			throw new AssertionError(e);
		}
	}

	<T> PcodeUseropLibrary<T> reflect(String name, CompilerSpec cSpec) {
		Lookup lookup = MethodHandles.lookup();
		try {
			return (PcodeUseropLibrary<T>) lookup
					.findConstructor(lookup.findClass(name),
						MethodType.methodType(void.class, CompilerSpec.class))
					.invoke(cSpec);
		}
		catch (Throwable e) {
			throw new AssertionError(e);
		}
	}

	@Test
	public void testViaJavaCallbacks() throws Exception {
		runTestOnEmulator(new PcodeEmulator(language) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return reflect("ModelingScript$JavaStdLibPcodeUseropLibrary", language);
			}
		});
	}

	@Test
	public void testViaSleighDefs() throws Exception {
		runTestOnEmulator(new PcodeEmulator(language) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return reflect("ModelingScript$SleighStdLibPcodeUseropLibrary");
			}
		});
	}

	@Test
	public void testViaStructuredSleigh() throws Exception {
		CompilerSpec gcc = language.getCompilerSpecByID(new CompilerSpecID("gcc"));
		runTestOnEmulator(new PcodeEmulator(language) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return reflect("ModelingScript$StructuredStdLibPcodeUseropLibrary", gcc);
			}
		});
	}

	static class TestJitPcodeEmulator extends JitPcodeEmulator {

		public TestJitPcodeEmulator(Language language) {
			super(language, new JitConfiguration(), MethodHandles.lookup());
		}

		@Override
		protected JitPcodeThread createThread(String name) {
			return new JitPcodeThread(name, this) {
				int count = 0;

				@Override
				public void count(int instructions, int trailingOps) {
					count += instructions + trailingOps;
					if (count > 1000000) {
						fail("Probably an infinite loop");
					}
				}
			};
		}
	}

	@Test
	public void testViaJavaCallbacksJit() throws Exception {
		runTestOnEmulator(new TestJitPcodeEmulator(language) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return reflect("ModelingScript$JavaStdLibPcodeUseropLibrary", language);
			}
		});
	}

	@Test
	public void testViaSleighDefsJit() throws Exception {
		runTestOnEmulator(new TestJitPcodeEmulator(language) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return reflect("ModelingScript$SleighStdLibPcodeUseropLibrary");
			}
		});
	}

	@Test
	public void testViaStructuredSleighJit() throws Exception {
		CompilerSpec gcc = language.getCompilerSpecByID(new CompilerSpecID("gcc"));
		runTestOnEmulator(new TestJitPcodeEmulator(language) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return reflect("ModelingScript$StructuredStdLibPcodeUseropLibrary", gcc);
			}
		});
	}
}
