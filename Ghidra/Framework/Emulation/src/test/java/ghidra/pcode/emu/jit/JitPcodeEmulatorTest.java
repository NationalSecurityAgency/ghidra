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

import static org.junit.Assert.*;

import java.lang.invoke.MethodHandles;

import org.junit.Test;

import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyBuffer;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;

public class JitPcodeEmulatorTest extends AbstractPcodeEmulatorTest {

	public static class TestUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {
		public int value4;
		public long value8;

		@PcodeUserop(functional = true, hasSideEffects = true)
		public void capture4(int value4) {
			this.value4 = value4;
		}

		@PcodeUserop(functional = true, hasSideEffects = true)
		public void capture8(long value8) {
			this.value8 = value8;
		}
	}

	TestUseropLibrary lib = new TestUseropLibrary();

	@Override
	protected JitPcodeEmulator createEmulator(Language language) {
		return new JitPcodeEmulator(language, new JitConfiguration(), MethodHandles.lookup()) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return super.createUseropLibrary().compose(lib);
			}
		};
	}

	@Test
	public void testDropAtDecodeError() throws Throwable {
		JitPcodeEmulator emu = createEmulator(getLanguage(LANGID_TOY_BE));
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r0,#123");
		asm.assemble("add r0,#7");
		Address after = asm.getNext();

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		JitPcodeThread thread = emu.newThread();
		EntryPoint entry = thread.getEntry(new AddrCtx(null, asm.getEntry()));
		try {
			entry.passage().run(0);
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
		}

		assertEquals(after, thread.getCounter());
	}

	@Test
	public void testDropAtExistingEntry() throws Throwable {
		JitPcodeEmulator emu = createEmulator(getLanguage(LANGID_TOY_BE));
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r0,#123");
		Address i2 = asm.getNext();
		asm.assemble("add r0,#7");

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		JitPcodeThread thread = emu.newThread();
		EntryPoint second = thread.getEntry(new AddrCtx(null, i2));
		EntryPoint first = thread.getEntry(new AddrCtx(null, asm.getEntry()));

		assertEquals(second, first.run());
		assertEquals(i2, thread.getCounter());
	}

	@Test
	public void testRunInvolvesTranslation() throws Throwable {
		JitPcodeEmulator emu = createEmulator(getLanguage(LANGID_TOY_BE));
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r0,#123");
		asm.assemble("add r0,#7");

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		JitPcodeThread thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());

		assertFalse(thread.hasEntry(new AddrCtx(null, asm.getEntry())));

		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
		}

		assertTrue(thread.hasEntry(new AddrCtx(null, asm.getEntry())));
	}

	public void runTestLowSubValReads(LanguageID langID) throws Exception {
		JitPcodeEmulator emu = createEmulator(getLanguage(langID));
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r0, #0x123"); // Not really used
		Address injectAt = asm.getNext();
		asm.assemble("or r1, r1"); // an instruction to inject o

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		JitPcodeThread thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());
		thread.overrideContextWithDefault();
		thread.inject(injectAt, """
				r0 = 0x1122334455667788;
				capture4(r0l);
				emu_exec_decoded();
				""");

		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
			// expected
		}

		assertEquals(0x55667788, lib.value4);
	}

	@Test
	public void testLowSubValReadsBE() throws Exception {
		runTestLowSubValReads(LANGID_TOY_BE);
	}

	@Test
	public void testLowSubValReadsLE() throws Exception {
		runTestLowSubValReads(LANGID_TOY_LE);
	}

	public void runTestLowSubValWrites(LanguageID langID) throws Exception {
		JitPcodeEmulator emu = createEmulator(getLanguage(langID));
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r0, #0x123"); // Not really used
		Address injectAt = asm.getNext();
		asm.assemble("or r1, r1"); // an instruction to inject o

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		JitPcodeThread thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());
		thread.overrideContextWithDefault();
		thread.inject(injectAt, """
				r0 = 0x1122334455667788;
				r0l = 0x44332211;
				capture8(r0);
				emu_exec_decoded();
				""");

		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
			// expected
		}

		assertEquals(0x1122334444332211L, lib.value8);
	}

	@Test
	public void testLowSubValWritesBE() throws Exception {
		runTestLowSubValWrites(LANGID_TOY_BE);
	}

	@Test
	public void testLowSubValWritesLE() throws Exception {
		runTestLowSubValWrites(LANGID_TOY_LE);
	}

	public void runTestHighSubValReads(LanguageID langID) throws Exception {
		JitPcodeEmulator emu = createEmulator(getLanguage(langID));
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r0, #0x123"); // Not really used
		Address injectAt = asm.getNext();
		asm.assemble("or r1, r1"); // an instruction to inject o

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		JitPcodeThread thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());
		thread.overrideContextWithDefault();
		thread.inject(injectAt, """
				r0 = 0x1122334455667788;
				capture4(r0h);
				emu_exec_decoded();
				""");

		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
			// expected
		}

		assertEquals(0x11223344, lib.value4);
	}

	@Test
	public void testHighSubValReadsBE() throws Exception {
		runTestHighSubValReads(LANGID_TOY_BE);
	}

	@Test
	public void testHighSubValReadsLE() throws Exception {
		runTestHighSubValReads(LANGID_TOY_LE);
	}

	public void runTestHighSubValWrites(LanguageID langID) throws Exception {
		JitPcodeEmulator emu = createEmulator(getLanguage(langID));
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r0, #0x123"); // Not really used
		Address injectAt = asm.getNext();
		asm.assemble("or r1, r1"); // an instruction to inject o

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		JitPcodeThread thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());
		thread.overrideContextWithDefault();
		thread.inject(injectAt, """
				r0 = 0x1122334455667788;
				r0h = 0x44332211;
				capture8(r0);
				emu_exec_decoded();
				""");

		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
			// expected
		}

		assertEquals(0x4433221155667788L, lib.value8);
	}

	@Test
	public void testHighSubValWritesBE() throws Exception {
		runTestHighSubValWrites(LANGID_TOY_BE);
	}

	@Test
	public void testHighSubValWritesLE() throws Exception {
		runTestHighSubValWrites(LANGID_TOY_LE);
	}
}
