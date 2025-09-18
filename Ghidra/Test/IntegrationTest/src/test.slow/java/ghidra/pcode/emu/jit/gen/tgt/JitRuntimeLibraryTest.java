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

import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.Test;

import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.MpDivPrivate;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.MpShiftPrivate;

public class JitRuntimeLibraryTest {

	int[] intsLE(int... legs) {
		ArrayUtils.reverse(legs);
		return legs;
	}

	String mpToString(int[] legs) {
		List<String> strs = IntStream.of(legs).mapToObj(i -> "%08x".formatted(i)).toList();
		return strs.reversed().stream().collect(Collectors.joining(":"));
	}

	void assertMpEquals(int[] expected, int[] actual) {
		assertEquals(mpToString(expected), mpToString(actual));
	}

	int[] out(int size, Consumer<int[]> func) {
		int[] out = new int[size];
		func.accept(out);
		return out;
	}

	@Test
	public void testMpShiftPrivateShl() {
		assertMpEquals(intsLE(0x89abcdef, 0xfedcba98, 0x76543210, 0x00000000),
			out(4, o -> MpShiftPrivate.shl(o,
				intsLE(0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210), 32)));
		assertMpEquals(intsLE(0x9abcdeff, 0xedcba987, 0x65432100, 0x00000000),
			out(4, o -> MpShiftPrivate.shl(o,
				intsLE(0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210), 36)));
		assertMpEquals(intsLE(0xedcba987, 0x65432100, 0x00000000),
			out(3, o -> MpShiftPrivate.shl(o,
				intsLE(0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210), 36)));
		assertMpEquals(intsLE(0x00000000, 0x9abcdeff, 0xedcba987, 0x65432100, 0x00000000),
			out(5, o -> MpShiftPrivate.shl(o,
				intsLE(0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210), 36)));
	}

	@Test
	public void testMpShiftPrivateUshr() {
		assertMpEquals(intsLE(0x00000000, 0x01234567, 0x89abcdef, 0xfedcba98),
			out(4, o -> MpShiftPrivate.ushr(o,
				intsLE(0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210), 32)));
		assertMpEquals(intsLE(0x00000000, 0x00123456, 0x789abcde, 0xffedcba9),
			out(4, o -> MpShiftPrivate.ushr(o,
				intsLE(0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210), 36)));
		assertMpEquals(intsLE(0x00123456, 0x789abcde, 0xffedcba9),
			out(3, o -> MpShiftPrivate.ushr(o,
				intsLE(0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210), 36)));
		assertMpEquals(intsLE(0x00000000, 0x00000000, 0x00123456, 0x789abcde, 0xffedcba9),
			out(5, o -> MpShiftPrivate.ushr(o,
				intsLE(0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210), 36)));
	}

	@Test
	public void testMpDivPrivateLz() {
		assertEquals(0, MpDivPrivate.lz(intsLE(-1)));
		assertEquals(1, MpDivPrivate.lz(intsLE(Integer.MAX_VALUE)));
		assertEquals(64, MpDivPrivate.lz(intsLE(0, 0, -1)));
	}

	@Test
	public void testMpDivPrivateShl() {
		int[] ints = intsLE(0xffffffff, 0x12345678);
		MpDivPrivate.shl(ints, 4);
		assertMpEquals(intsLE(0xfffffff1, 0x23456780), ints);
	}

	@Test
	public void testMpDivPrivateShr() {
		int[] ints = intsLE(0x12345678, 0xffffffff);
		MpDivPrivate.shr(ints, 4);
		assertMpEquals(intsLE(0x01234567, 0x8fffffff), ints);
	}

	@Test
	public void testMpDivPrivateNeg() {
		int[] ints;

		ints = intsLE(0x00000000, 0x00000000);
		MpDivPrivate.neg(ints, 2);
		assertMpEquals(intsLE(0x00000000, 0x00000000), ints);

		ints = intsLE(0x80000000, 0x00000000);
		MpDivPrivate.neg(ints, 2);
		assertMpEquals(intsLE(0x80000000, 0x00000000), ints);

		ints = intsLE(0xffffffff, 0xffff0000);
		MpDivPrivate.neg(ints, 2);
		assertMpEquals(intsLE(0x00000000, 0x00010000), ints);
	}
}
