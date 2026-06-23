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
package ghidra.pcodeCPort.slgh_compile;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import utilities.util.FileUtilities;

public class SleighCompileOptionsTest extends AbstractGenericTest {
	@Test
	public void testArgFile() throws IOException {
		File argTmp = createTempFile("sleigh_args");
		FileUtilities.writeStringToFile(argTmp, """
				-x
				-u
				-l
				-n
				-t
				-e
				-c
				-f
				-s
				-DTESTNAME=TESTVALUE
				-dx86
				""");

		// test default -x before doing any option parsing because its a global flag
		assertFalse(SleighCompile.yydebug);

		SleighCompileOptions defaultOpts = new SleighCompileOptions();
		SleighCompileOptions opts = SleighCompileOptions.fromFile(argTmp);

		// -x
		assertTrue(SleighCompile.yydebug);

		// -u
		assertTrue(opts.unnecessaryPcodeWarning);
		assertNotEquals(defaultOpts.unnecessaryPcodeWarning, opts.unnecessaryPcodeWarning);

		// -l
		assertFalse(opts.lenientConflict);
		assertNotEquals(defaultOpts.lenientConflict, opts.lenientConflict);

		// -n
		assertTrue(opts.allNopWarning);
		assertNotEquals(defaultOpts.allNopWarning, opts.allNopWarning);

		// -t
		assertTrue(opts.deadTempWarning);
		assertNotEquals(defaultOpts.deadTempWarning, opts.deadTempWarning);

		// -e
		assertTrue(opts.enforceLocalKeyWord);
		assertNotEquals(defaultOpts.enforceLocalKeyWord, opts.enforceLocalKeyWord);

		// -c
		assertTrue(opts.allCollisionWarning);
		assertNotEquals(defaultOpts.allCollisionWarning, opts.allCollisionWarning);

		// -f
		assertTrue(opts.unusedFieldWarning);
		assertNotEquals(defaultOpts.unusedFieldWarning, opts.unusedFieldWarning);

		// -s
		assertTrue(opts.caseSensitiveRegisterNames);
		assertNotEquals(defaultOpts.caseSensitiveRegisterNames, opts.caseSensitiveRegisterNames);

		// -D
		assertNull(defaultOpts.preprocs.get("TESTNAME"));
		assertEquals("TESTVALUE", opts.preprocs.get("TESTNAME"));

		// -d
		assertNull(defaultOpts.preprocs.get("x86"));
		assertNotNull(opts.preprocs.get("x86"));
		assertTrue(new File(opts.preprocs.get("x86")).isDirectory());
	}

	@Test
	public void testCmdLineArgs_1input() throws IOException {
		File argTmp = createTempFile("sleigh_args");
		FileUtilities.writeStringToFile(argTmp, "-DTESTNAME=TESTVALUE");

		String[] args = { "-i", argTmp.getPath(), "inputfile.slaspec" };
		SleighCompileOptions opts = SleighCompileOptions.parse(args);

		assertEquals("TESTVALUE", opts.preprocs.get("TESTNAME"));
		assertEquals(opts.inputFile.getName(), "inputfile.slaspec");
		assertEquals(opts.outputFile.getName(), "inputfile.sla");
	}

	@Test
	public void testCmdLineArgs_1input_default_ext() throws IOException {
		File argTmp = createTempFile("sleigh_args");
		FileUtilities.writeStringToFile(argTmp, "-DTESTNAME=TESTVALUE");

		String[] args = { "-i", argTmp.getPath(), "inputfile" };
		SleighCompileOptions opts = SleighCompileOptions.parse(args);

		assertEquals("TESTVALUE", opts.preprocs.get("TESTNAME"));
		assertEquals(opts.inputFile.getName(), "inputfile.slaspec");
		assertEquals(opts.outputFile.getName(), "inputfile.sla");
	}

	@Test
	public void testCmdLineArgs_input_and_output() throws IOException {
		File argTmp = createTempFile("sleigh_args");
		FileUtilities.writeStringToFile(argTmp, "-DTESTNAME=TESTVALUE");

		String[] args = { "-i", argTmp.getPath(), "inputfile.slaspec", "outputfile.sla" };
		SleighCompileOptions opts = SleighCompileOptions.parse(args);

		assertEquals("TESTVALUE", opts.preprocs.get("TESTNAME"));
		assertEquals(opts.inputFile.getName(), "inputfile.slaspec");
		assertEquals(opts.outputFile.getName(), "outputfile.sla");
	}

	@Test
	public void testCmdLineArgs_all() throws IOException {
		File argTmp = createTempFile("sleigh_args");
		FileUtilities.writeStringToFile(argTmp, "-DTESTNAME=TESTVALUE");
		File allDir = createTempDirectory("alldir");

		String[] args = { "-i", argTmp.getPath(), "-a", allDir.getPath() };
		SleighCompileOptions opts = SleighCompileOptions.parse(args);

		assertEquals("TESTVALUE", opts.preprocs.get("TESTNAME"));
		assertTrue(opts.allMode);
		assertEquals(opts.allDir.getPath(), allDir.getPath());
	}

}
