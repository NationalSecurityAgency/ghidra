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
package ghidra.app.plugin.core.decompiler.taint;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import ghidra.program.model.address.*;

/**
 * Unit tests for the string/identity logic in {@link TaintQueryResult}.  These exercise the
 * fqname conventions of both ctadl (python) and ctadl-rs:
 * <ul>
 * <li>ctadl variables: {@code func@entry::varname) (fqname). names like {@code func:var}</li>
 * <li>ctadl instructions: {@code func@entry:insn:time}</li>
 * <li>ctadl-rs instructions: {@code func@00401000:00401000} (hex, zero-padded)/li>
 * <li>ctadl-rs function endpoints: bare function name, no "@" part</li>
 * <li>ctadl-rs globals: {@code prog::globalName}</li>
 * </ul>
 */
public class TaintQueryResultTest {

	private final AddressSpace space =
		new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testContainsSegment() {
		// exact segment bounded by separators
		assertTrue(TaintQueryResult.containsSegment("main@00410000::buf", "buf"));
		assertTrue(TaintQueryResult.containsSegment("main@00410000::buf:3", "buf"));
		assertTrue(TaintQueryResult.containsSegment("prog::g_data", "g_data"));
		// at start
		assertTrue(TaintQueryResult.containsSegment("buf:00410000", "buf"));

		// substring false-positives must be rejected
		assertFalse(TaintQueryResult.containsSegment("main@00410000::buf2", "buf"));
		assertFalse(TaintQueryResult.containsSegment("main@00410000::my_buf", "buf"));
		assertFalse(TaintQueryResult.containsSegment("prog::g_data2", "g_data"));

		// degenerate inputs
		assertFalse(TaintQueryResult.containsSegment(null, "buf"));
		assertFalse(TaintQueryResult.containsSegment("main::buf", null));
		assertFalse(TaintQueryResult.containsSegment("main::buf", ""));
	}

	@Test
	public void testEndsWithSegment() {
		assertTrue(TaintQueryResult.endsWithSegment("main:buf", "buf"));
		assertTrue(TaintQueryResult.endsWithSegment("main@00410000::buf", "buf"));
		assertTrue(TaintQueryResult.endsWithSegment("buf", "buf"));

		assertFalse(TaintQueryResult.endsWithSegment("main:my_buf", "buf"));
		assertFalse(TaintQueryResult.endsWithSegment("main::buf2", "buf"));
		assertFalse(TaintQueryResult.endsWithSegment(null, "buf"));
		assertFalse(TaintQueryResult.endsWithSegment("main::buf", null));
	}

	@Test
	public void testStartsWithSegment() {
		assertTrue(TaintQueryResult.startsWithSegment("main@00410000", "main"));
		assertTrue(TaintQueryResult.startsWithSegment("main:00410000", "main"));
		assertTrue(TaintQueryResult.startsWithSegment("main", "main"));

		assertFalse(TaintQueryResult.startsWithSegment("maintain@00410000", "main"));
		assertFalse(TaintQueryResult.startsWithSegment("main2@00410000", "main"));
	}

	@Test
	public void testEqualityExcludesMutableLabels() {
		TaintQueryResult a = new TaintQueryResult("main:buf", "main@00410000::buf", addr(0x401010),
			addr(0x401000), new ArrayList<>(), false);
		TaintQueryResult b = new TaintQueryResult("main:buf", "main@00410000::buf", addr(0x401010),
			addr(0x401000), new ArrayList<>(), false);

		assertEquals(a, b);
		assertEquals(a.hashCode(), b.hashCode());

		Set<TaintQueryResult> set = new HashSet<>();
		set.add(a);

		// mutating labels after insertion must not change identity
		a.addLabel("SOURCE");
		b.addLabel("SINK");
		assertEquals(a, b);
		assertEquals(a.hashCode(), b.hashCode());
		assertTrue(set.contains(a));
		assertTrue("removal by equal value must still work", set.remove(b));
	}

	@Test
	public void testMatchesFunction() {
		TaintQueryResult r = new TaintQueryResult("main:x", "main@00410000::x", addr(0x401000),
			addr(0x401000), new ArrayList<>(), false);
		assertTrue(r.matchesFunction("main", addr(0x401000)));
		assertFalse(r.matchesFunction("main", addr(0x402000)));
		assertFalse(r.matchesFunction("maintain", addr(0x401000)));

		// function-level result without any addresses (e.g. ctadl-rs bare-name endpoint):
		// matches by name alone and must not throw
		TaintQueryResult bare =
			new TaintQueryResult("main", "main", null, null, new ArrayList<>(), true);
		assertTrue(bare.matchesFunction("main", addr(0x401000)));
		assertFalse(r.matchesFunction("ther", addr(0x401000)));
	}

	@Test
	public void testGetLabelOnEmptyLabels() {
		TaintQueryResult r =
			new TaintQueryResult("main", "main", null, null, new ArrayList<>(), true);
		assertNull(r.getLabel());
		r.addLabel(null);  // must be a no-op, not an NPE later
		assertNull(r.getLabel());
		r.addLabel("SOURCE");
		assertEquals("SOURCE", r.getLabel());
	}
}

