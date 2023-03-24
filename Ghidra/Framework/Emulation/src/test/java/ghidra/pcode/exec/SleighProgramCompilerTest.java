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
package ghidra.pcode.exec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import generic.Unique;
import generic.test.AbstractGTest;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageHelper;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.pcode.exec.SleighProgramCompiler.DetailedSleighException;
import ghidra.pcode.exec.SleighProgramCompiler.PcodeLogEntry;
import ghidra.sleigh.grammar.Location;
import utility.function.ExceptionalCallback;

public class SleighProgramCompilerTest extends AbstractGTest {
	protected <T> T rfail(String message) {
		fail(message);
		throw new AssertionError();
	}

	protected <E extends Exception> E expect(Class<E> cls, ExceptionalCallback<E> cb) {
		try {
			cb.call();
		}
		catch (Throwable e) {
			if (!cls.isInstance(e)) {
				e.printStackTrace();
				return rfail("Expected " + cls + ". Got " + e.getClass());
			}
			return cls.cast(e);
		}
		return rfail("Expected " + cls + ". Got success");
	}

	@Before
	public void setUp() throws IOException {
		if (!Application.isInitialized()) {
			Application.initializeApplication(
				new GhidraTestApplicationLayout(new File(getTestDirectoryPath())),
				new ApplicationConfiguration());
		}
	}

	@Test
	public void testCompileProgramErrLocations() throws Throwable {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();
		DetailedSleighException exc = expect(DetailedSleighException.class, () -> {
			PcodeProgram program =
				SleighProgramCompiler.compileProgram(language, "test", "noreg = noreg;",
					PcodeUseropLibrary.NIL);
			// Shouldn't get here, but if we do, I'd like to see the program:
			System.err.println(program);
		});
		PcodeLogEntry entry = Unique.assertOne(exc.getDetails());
		Location loc = entry.loc();
		assertEquals("test", loc.filename);
		assertEquals(1, loc.lineno);
		assertEquals(
			"unknown start, end, next2, operand, epsilon, or varnode 'noreg' in varnode reference",
			entry.msg());
	}

	@Test
	public void testCompileExpressionErrLocations() throws Throwable {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();
		DetailedSleighException exc = expect(DetailedSleighException.class, () -> {
			PcodeProgram program = SleighProgramCompiler.compileExpression(language, "noreg");
			// Shouldn't get here, but if we do, I'd like to see the program:
			System.err.println(program);
		});
		PcodeLogEntry entry = Unique.assertOne(exc.getDetails());
		// TODO: It'd be nice if loc included a column number and token length
		Location loc = entry.loc();
		assertEquals("expression", loc.filename);
		assertEquals(1, loc.lineno);
		assertEquals(
			"unknown start, end, next2, operand, epsilon, or varnode 'noreg' in varnode reference",
			entry.msg());
	}
}
