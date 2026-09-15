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
package ghidra.feature.fid.db;

import static org.junit.Assert.*;

import java.util.HashSet;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.sourcelanguage.SourceLanguageID;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

public class FidFilterTest extends AbstractGenericTest {

	private LanguageID x64, arm64;
	private CompilerSpecID winSpec, gccSpec;
	private Set<SourceLanguageID> sourceSet;
	private Set<SourceLanguageID> multiSourceSet;
	private FidProgramID prog1, prog2, prog3, prog4;

	@Before
	public void setup() {
		x64 = new LanguageID("x86:LE:64:default");
		arm64 = new LanguageID("AARCH64:LE:64:v8A");
		winSpec = new CompilerSpecID("windows");
		gccSpec = new CompilerSpecID("gcc");
		sourceSet = new HashSet<>();
		sourceSet.add(new SourceLanguageID("rust"));
		multiSourceSet = new HashSet<>();
		multiSourceSet.add(new SourceLanguageID("rust"));
		multiSourceSet.add(new SourceLanguageID("swift"));

		prog1 = new FidProgramID(x64, gccSpec, multiSourceSet);
		prog2 = new FidProgramID(x64, winSpec, null);
		prog3 = new FidProgramID(arm64, winSpec, sourceSet);
		prog4 = new FidProgramID(x64, winSpec, sourceSet);
	}

	@Test
	public void testFidProgramIDEquality() {
		assertFalse(prog1.equals(prog2));
		assertFalse(prog3.equals(prog4));
		FidProgramID newProg = new FidProgramID(x64, winSpec, null);
		assertTrue(prog2.equals(newProg));
		FidProgramID nullProg = new FidProgramID();
		assertFalse(nullProg.equals(prog4));
	}

	@Test
	public void testFilter() {
		FidFilter filter1 = new FidFilter("x86:LE:64:default", "gcc", "rust");
		assertTrue(filter1.test(prog1));
		assertFalse(filter1.test(prog2));
		assertFalse(filter1.test(prog3));
		assertFalse(filter1.test(prog4));
		FidFilter filter2 = new FidFilter("x86:LE:64:variant", null, "rust");
		assertTrue(filter2.test(prog1));
		assertTrue(filter2.test(prog2));
		assertFalse(filter2.test(prog3));
		assertTrue(filter2.test(prog4));
		FidFilter filter3 = new FidFilter("x86:LE:64:default", "other,gcc", "rust,other");
		assertTrue(filter3.test(prog1));
		assertFalse(filter3.test(prog2));
		assertFalse(filter3.test(prog3));
		assertFalse(filter3.test(prog4));
		FidFilter filter4 = new FidFilter("AARCH64:LE:64:variant", "windows,other", null);
		assertFalse(filter4.test(prog1));
		assertFalse(filter4.test(prog2));
		assertTrue(filter4.test(prog3));
		assertFalse(filter4.test(prog4));
	}

	@Test
	public void testNoneFilter() {
		FidFilter filter = new FidFilter();
		assertFalse(filter.test(prog1));
		assertFalse(filter.test(prog2));
		assertFalse(filter.test(prog3));
		assertFalse(filter.test(prog4));
	}

	@Test
	public void testAnyProgram() {
		FidProgramID prog = new FidProgramID();
		FidFilter filter = new FidFilter("x86:LE:64:default", "other,gcc", "rust,other");
		assertTrue(filter.test(prog));
	}
}
