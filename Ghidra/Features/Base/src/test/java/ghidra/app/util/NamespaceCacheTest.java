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
package ghidra.app.util;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGuiTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.ToyProgramBuilder;

public class NamespaceCacheTest extends AbstractGuiTest {

	private Namespace a;
	private Namespace b;
	private Namespace c;
	private Namespace d;
	private Namespace e;
	private Namespace f;
	private Namespace g;
	private Namespace h;
	private Namespace i;
	private Namespace j;
	private Namespace k;
	private ProgramDB program;

	@Before
	public void setup() throws Exception {
		ProgramBuilder builder = new ToyProgramBuilder("Test", false, this);
		a = builder.createNamespace("a");
		b = builder.createNamespace("b", "a", SourceType.USER_DEFINED);
		c = builder.createNamespace("c", "a::b", SourceType.USER_DEFINED);
		d = builder.createNamespace("d");
		e = builder.createNamespace("e");
		f = builder.createNamespace("f");
		g = builder.createNamespace("g");
		h = builder.createNamespace("h");
		i = builder.createNamespace("i");
		j = builder.createNamespace("j");
		k = builder.createNamespace("k");
		program = builder.getProgram();
	}

	@Test
	public void testGetRecent() {
		NamespaceCache.add(program, a);
		NamespaceCache.add(program, b);
		NamespaceCache.add(program, c);

		List<Namespace> recent = NamespaceCache.get(program);
		assertEquals(c, recent.get(0));
		assertEquals(b, recent.get(1));
		assertEquals(a, recent.get(2));
	}

	@Test
	public void testMostRecentAtTop() {
		NamespaceCache.add(program, a);
		NamespaceCache.add(program, b);
		NamespaceCache.add(program, c);
		NamespaceCache.add(program, a);

		List<Namespace> recents = NamespaceCache.get(program);
		assertEquals(3, recents.size());
		assertEquals(a, recents.get(0));
		assertEquals(c, recents.get(1));
		assertEquals(b, recents.get(2));
	}

	@Test
	public void testMaxRecents() {
		NamespaceCache.add(program, a);
		NamespaceCache.add(program, b);
		NamespaceCache.add(program, c);
		NamespaceCache.add(program, d);
		NamespaceCache.add(program, e);
		NamespaceCache.add(program, f);
		NamespaceCache.add(program, g);
		NamespaceCache.add(program, h);
		NamespaceCache.add(program, i);
		NamespaceCache.add(program, j);
		NamespaceCache.add(program, k);

		List<Namespace> recents = NamespaceCache.get(program);
		assertEquals(NamespaceCache.MAX_RECENTS, recents.size());
		assertEquals(k, recents.get(0));
		assertEquals(b, recents.get(9));
	}

	@Test
	public void testClosingProgramClearsRecents() {
		NamespaceCache.add(program, a);
		NamespaceCache.add(program, b);
		NamespaceCache.add(program, c);

		List<Namespace> recents = NamespaceCache.get(program);
		assertEquals(3, recents.size());

		program.release(this);

		recents = NamespaceCache.get(program);
		assertTrue(recents.isEmpty());

	}

}
