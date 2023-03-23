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
package ghidra.trace.database.memory;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

import db.Transaction;
import ghidra.program.model.lang.*;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.thread.TraceThread;

public abstract class AbstractDBTraceMemoryManagerRegistersTest
		extends AbstractDBTraceMemoryManagerTest {

	protected TraceThread getOrAddThread(String name, long creationSnap) {
		return b.getOrAddThread(name, creationSnap);
	}

	protected abstract boolean isRegistersPerFrame();

	@Test
	public void testRegisters() throws Exception {
		Register r0 = b.language.getRegister("r0");
		Register r0h = b.language.getRegister("r0h");
		Register r0l = b.language.getRegister("r0l");

		TraceThread thread;
		try (Transaction tx = b.startTransaction()) {
			thread = getOrAddThread("Threads[1]", 0);
			DBTraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);

			regs.setValue(0, new RegisterValue(r0, new BigInteger("0123456789ABCDEF", 16)));
			assertEquals(new BigInteger("0123456789ABCDEF", 16),
				regs.getValue(0, r0).getUnsignedValue());

			regs.setValue(0, new RegisterValue(r0h, new BigInteger("76543210", 16)));
			assertEquals(new BigInteger("7654321089ABCDEF", 16),
				regs.getValue(0, r0).getUnsignedValue());
			assertEquals(new BigInteger("76543210", 16), regs.getValue(0, r0h).getUnsignedValue());
			assertEquals(new BigInteger("89ABCDEF", 16), regs.getValue(0, r0l).getUnsignedValue());

			regs.setValue(0, new RegisterValue(r0l, new BigInteger("FEDCBA98", 16)));
			assertEquals(new BigInteger("76543210FEDCBA98", 16),
				regs.getValue(0, r0).getUnsignedValue());
			assertEquals(new BigInteger("76543210", 16), regs.getValue(0, r0h).getUnsignedValue());
			assertEquals(new BigInteger("FEDCBA98", 16), regs.getValue(0, r0l).getUnsignedValue());

			TraceStack stack = b.trace.getStackManager().getStack(thread, 0, true);
			stack.setDepth(2, true);
			assertSame(regs, memory.getMemoryRegisterSpace(stack.getFrame(0, false), false));
			DBTraceMemorySpace frame =
				memory.getMemoryRegisterSpace(stack.getFrame(1, false), true);
			if (isRegistersPerFrame()) {
				assertNotSame(regs, frame);
			}
			else {
				assertSame(regs, frame);
			}

			frame.setValue(0, new RegisterValue(r0, new BigInteger("1032547698BADCFE", 16)));
			assertEquals(new BigInteger("1032547698BADCFE", 16),
				frame.getValue(0, r0).getUnsignedValue());
		}
	}

	/**
	 * This has to be called by the sub-class, having created a trace with the Toy:??:32:builder
	 * language.
	 */
	protected void runTestRegisterBits(TracePlatform platform) throws Exception {
		Language language = platform.getLanguage();
		Register contextreg = language.getRegister("contextreg");
		Register fctx = language.getRegister("fctx");
		Register nfctx = language.getRegister("nfctx");
		Register phase = language.getRegister("phase");
		Register counter = language.getRegister("counter");

		TraceThread thread;
		try (Transaction tx = b.startTransaction()) {
			thread = getOrAddThread("Threads[1]", 0);
			waitForSwing();
			DBTraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);

			regs.setValue(platform, 0, new RegisterValue(fctx, BigInteger.valueOf(0xa)));
			assertEquals(BigInteger.valueOf(0xa),
				regs.getValue(platform, 0, fctx).getUnsignedValue());

			regs.setValue(platform, 0, new RegisterValue(nfctx, BigInteger.valueOf(0xb)));
			assertEquals(BigInteger.valueOf(0xb),
				regs.getValue(platform, 0, nfctx).getUnsignedValue());
			assertEquals(BigInteger.valueOf(0xa),
				regs.getValue(platform, 0, fctx).getUnsignedValue());

			regs.setValue(platform, 0, new RegisterValue(phase, BigInteger.valueOf(0x3)));
			assertEquals(BigInteger.valueOf(0x3),
				regs.getValue(platform, 0, phase).getUnsignedValue());
			assertEquals(BigInteger.valueOf(0),
				regs.getValue(platform, 0, counter).getUnsignedValue());

			regs.setValue(platform, 0, new RegisterValue(counter, BigInteger.valueOf(0xf)));
			assertEquals(BigInteger.valueOf(0xf),
				regs.getValue(platform, 0, counter).getUnsignedValue());

			assertEquals("abfc000000000000",
				regs.getValue(platform, 0, contextreg).getUnsignedValue().toString(16));

			regs.setValue(platform, 0, new RegisterValue(fctx, BigInteger.valueOf(0x5)));
			assertEquals("5bfc000000000000",
				regs.getValue(platform, 0, contextreg).getUnsignedValue().toString(16));
		}
	}

	/**
	 * This test is based on the MWE submitted in GitHub issue #2760.
	 */
	@Test
	public void testManyStateEntries() throws Exception {
		Register pc = b.language.getRegister("pc");
		TraceThread thread;
		try (Transaction tx = b.startTransaction()) {
			thread = getOrAddThread("Threads[1]", 0);
			DBTraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);

			for (int i = 1; i < 2000; i++) {
				//System.err.println("Snap " + i);
				regs.setState(i, pc, TraceMemoryState.KNOWN);
				//regs.stateMapSpace.checkIntegrity();
			}
		}
	}

	protected void runTestGuestMappingRegisterBits(LanguageID langID, CompilerSpecID cSpecID)
			throws Throwable {
		TraceGuestPlatform guest;
		try (Transaction tx = b.startTransaction()) {
			guest = b.trace.getPlatformManager()
					.addGuestPlatform(
						getLanguageService().getLanguage(langID).getCompilerSpecByID(cSpecID));
			guest.addMappedRegisterRange();
		}
		runTestRegisterBits(guest);
	}

	@Test
	// Test both BE and LE guest on both BE and LE hosts
	public void testGuestMappingBERegisterBits() throws Throwable {
		runTestGuestMappingRegisterBits(new LanguageID("Toy:BE:32:builder"),
			new CompilerSpecID("default"));
	}

	@Test
	// Test both BE and LE guest on both BE and LE hosts
	public void testGuestMappingLERegisterBits() throws Throwable {
		runTestGuestMappingRegisterBits(new LanguageID("Toy:LE:32:builder"),
			new CompilerSpecID("default"));
	}
}
