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

import java.io.File;
import java.lang.invoke.MethodHandles;
import java.math.BigInteger;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.DecodePcodeExecutionException;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

@Ignore("For developer workstation")
public class JitMpIntPerformanceExperiment {
	public static final int N = 100_000_000;
	public static final BigInteger MASK_16_BYTES =
		BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
	private static SleighLanguage toy;

	@BeforeClass
	public static void setUp() throws Exception {
		Application.initializeApplication(
			new GhidraTestApplicationLayout(new File(AbstractGenericTest.getTestDirectoryPath())),
			new ApplicationConfiguration());

		toy = (SleighLanguage) DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("Toy:BE:64:default"));
		Assemblers.getAssembler(toy);
	}

	@Test
	public void testSpeedBigInteger() {
		BigInteger previous = BigInteger.ZERO;
		BigInteger current = BigInteger.ONE;

		for (int i = 0; i < N; i++) {
			BigInteger next = previous.add(current);
			next = next.and(MASK_16_BYTES);
			previous = current;
			current = next;
		}

		System.out.println("fib(%d) = %s".formatted(N, current.toString(16)));
	}

	@Test
	public void testSpeedIntArray() {
		int[] previous = new int[] { 0, 0, 0, 0 };
		int[] current = new int[] { 1, 0, 0, 0 };
		int[] next = new int[4];

		for (int i = 0; i < N; i++) {
			doArrAdd(next, previous, current);
			int[] temp = previous;
			previous = current;
			current = next;
			next = temp;
		}

		System.out.println("fib(%d) = %08x%08x%08x%08x".formatted(N,
			current[3], current[2], current[1], current[0]));
	}

	@Test
	public void testSpeedIntArrayFinalLoop() {
		final int[] previous = new int[] { 0, 0, 0, 0 };
		final int[] current = new int[] { 1, 0, 0, 0 };
		final int[] next = new int[4];

		for (int i = 0; i < N; i++) {
			doArrAdd(next, previous, current);
			for (int j = 0; j < 4; j++) {
				previous[j] = current[j];
				current[j] = next[j];
			}
		}

		System.out.println("fib(%d) = %08x%08x%08x%08x".formatted(N,
			current[3], current[2], current[1], current[0]));
	}

	@Test
	public void testSpeedIntArrayFinalArrayCopy() {
		final int[] previous = new int[] { 0, 0, 0, 0 };
		final int[] current = new int[] { 1, 0, 0, 0 };
		final int[] next = new int[4];

		for (int i = 0; i < N; i++) {
			doArrAdd(next, previous, current);
			System.arraycopy(current, 0, previous, 0, 4);
			System.arraycopy(next, 0, current, 0, 4);
		}

		System.out.println("fib(%d) = %08x%08x%08x%08x".formatted(N,
			current[3], current[2], current[1], current[0]));
	}

	private static void doArrAdd(final int[] result, final int[] a, final int[] b) {
		long t = 0;
		for (int i = 0; i < 4; i++) {
			t += Integer.toUnsignedLong(a[i]);
			t += Integer.toUnsignedLong(b[i]);
			result[i] = (int) t;
			t >>>= 32;
		}
	}

	@Test
	public void testSpeedIntArrayInlined() {
		int[] previous = new int[] { 0, 0, 0, 0 };
		int[] current = new int[] { 1, 0, 0, 0 };
		int[] next = new int[4];

		for (int i = 0; i < N; i++) {
			long t = 0;
			for (int j = 0; j < 4; j++) {
				t += Integer.toUnsignedLong(previous[j]);
				t += Integer.toUnsignedLong(current[j]);
				next[j] = (int) t;
				t >>>= 32;
			}

			int[] temp = previous;
			previous = current;
			current = next;
			next = temp;
		}

		System.out.println("fib(%d) = %08x%08x%08x%08x".formatted(N,
			current[3], current[2], current[1], current[0]));
	}

	@Test
	public void testSpeedScalarized() {
		int prev0 = 0, prev1 = 0, prev2 = 0, prev3 = 0;
		int curr0 = 1, curr1 = 0, curr2 = 0, curr3 = 0;
		int next0, next1, next2, next3;

		for (int i = 0; i < N; i++) {
			long t = 0;
			t += Integer.toUnsignedLong(prev0);
			t += Integer.toUnsignedLong(curr0);
			next0 = (int) t;
			t >>>= 32;
			t += Integer.toUnsignedLong(prev1);
			t += Integer.toUnsignedLong(curr1);
			next1 = (int) t;
			t >>>= 32;
			t += Integer.toUnsignedLong(prev2);
			t += Integer.toUnsignedLong(curr2);
			next2 = (int) t;
			t >>>= 32;
			t += Integer.toUnsignedLong(prev3);
			t += Integer.toUnsignedLong(curr3);
			next3 = (int) t;

			prev0 = curr0;
			prev1 = curr1;
			prev2 = curr2;
			prev3 = curr3;

			curr0 = next0;
			curr1 = next1;
			curr2 = next2;
			curr3 = next3;
		}

		System.out.println("fib(%d) = %08x%08x%08x%08x".formatted(N,
			curr3, curr2, curr1, curr0));
	}

	static final long LONG_MASK = 0xffffffffL;

	@Test
	public void testSpeedScalarizedAnd() {
		int prev0 = 0, prev1 = 0, prev2 = 0, prev3 = 0;
		int curr0 = 1, curr1 = 0, curr2 = 0, curr3 = 0;
		int next0, next1, next2, next3;

		for (int i = 0; i < N; i++) {
			long t = 0;
			t += prev0 & LONG_MASK;
			t += curr0 & LONG_MASK;
			next0 = (int) t;
			t >>>= 32;
			t += prev1 & LONG_MASK;
			t += curr1 & LONG_MASK;
			next1 = (int) t;
			t >>>= 32;
			t += prev2 & LONG_MASK;
			t += curr2 & LONG_MASK;
			next2 = (int) t;
			t >>>= 32;
			t += prev3 & LONG_MASK;
			t += curr3 & LONG_MASK;
			next3 = (int) t;

			prev0 = curr0;
			prev1 = curr1;
			prev2 = curr2;
			prev3 = curr3;

			curr0 = next0;
			curr1 = next1;
			curr2 = next2;
			curr3 = next3;
		}

		System.out.println("fib(%d) = %08x%08x%08x%08x".formatted(N,
			curr3, curr2, curr1, curr0));
	}

	@Test
	public void testSpeedPlainEmu() {
		String sleigh = """
				counter:4 = 0;
				prev:16 = 0;
				curr:16 = 1;
				<loop>
				  next:16 = prev + curr;
				  prev = curr;
				  curr = next;
				  counter = counter + 1;
				if (counter < 0x%08x) goto <loop>;
				r0 = curr(0);
				r1 = curr(8);
				goto 0xdeadbeef;
				""".formatted(N);

		PcodeEmulator emu = new PcodeEmulator(toy);
		PcodeThread<byte[]> thread = emu.newThread();

		Address address = toy.getDefaultSpace().getAddress(0x00400000);
		thread.inject(address, sleigh);
		thread.overrideCounter(address);
		thread.reInitialize();

		try {
			thread.run();
		}
		catch (DecodePcodeExecutionException e) {
			if (e.getProgramCounter().getOffset() != 0xdeadbeef) {
				throw e;
			}
		}
		System.out.println("fib(%d) = %016x%016x".formatted(N,
			thread.getArithmetic()
					.toLong(thread.getState().getVar(toy.getRegister("r1"), Reason.INSPECT),
						Purpose.INSPECT),
			thread.getArithmetic()
					.toLong(thread.getState().getVar(toy.getRegister("r0"), Reason.INSPECT),
						Purpose.INSPECT)));
	}

	@Test
	public void testSpeedJitEmu() {
		String sleigh = """
				counter:4 = 0;
				prev:16 = 0;
				curr:16 = 1;
				<loop>
				  next:16 = prev + curr;
				  prev = curr;
				  curr = next;
				  counter = counter + 1;
				if (counter < 0x%08x) goto <loop>;
				r0 = curr(0);
				r1 = curr(8);
				goto 0xdeadbeef;
				""".formatted(N);

		JitPcodeEmulator emu =
			new JitPcodeEmulator(toy, new JitConfiguration(), MethodHandles.lookup());
		JitPcodeThread thread = emu.newThread();

		Address address = toy.getDefaultSpace().getAddress(0x00400000);
		thread.inject(address, sleigh);
		thread.overrideCounter(address);
		thread.reInitialize();

		try {
			thread.run();
		}
		catch (DecodePcodeExecutionException e) {
			if (e.getProgramCounter().getOffset() != 0xdeadbeef) {
				throw e;
			}
		}
		System.out.println("fib(%d) = %016x%016x".formatted(N,
			thread.getArithmetic()
					.toLong(thread.getState().getVar(toy.getRegister("r1"), Reason.INSPECT),
						Purpose.INSPECT),
			thread.getArithmetic()
					.toLong(thread.getState().getVar(toy.getRegister("r0"), Reason.INSPECT),
						Purpose.INSPECT)));
	}
}
