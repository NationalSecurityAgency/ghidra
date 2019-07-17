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
package ghidra.sleigh.grammar;

import static org.junit.Assert.assertTrue;

import java.io.*;
import java.net.URL;
import java.util.*;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.util.Msg;
import resources.ResourceManager;

public class SleighPreprocessorTest extends AbstractGenericTest {

	// only use logging locally
	private static final boolean DEBUG = !BATCH_MODE;

	private void debug(String s) {
		if (DEBUG) {
			Msg.debug(this, s);
		}
	}

	@Test
	public void testExternal() throws Exception {
		List<File> inputs = getInputFiles();
		List<File> targets = getTargetFiles();

		assertTrue(
			"Found 0 test input files; please fix this test so it finds them properly in the test environment",
			inputs.size() > 0);

		Assert.assertEquals("# inputs != # targets", inputs.size(), targets.size());

		Iterator<File> ii = inputs.iterator();
		Iterator<File> tt = targets.iterator();

		while (ii.hasNext()) {
			File inputFile = ii.next();
			File targetFile = tt.next();

			debug("testing " + inputFile);

			LineArrayListWriter output = new LineArrayListWriter();

			HashMapPreprocessorDefinitionsAdapter definitions =
				new HashMapPreprocessorDefinitionsAdapter();
			definitions.set("REPLACE", "includes");
			SleighPreprocessor sp = new SleighPreprocessor(definitions, inputFile);
			sp.process(output);

			if (DEBUG) {
				debug(new BufferedReader(new FileReader(inputFile)),
					new BufferedReader(new StringReader(output.toString())),
					new BufferedReader(new FileReader(targetFile)));
			}
			BufferedReader actual = new BufferedReader(new StringReader(output.toString()));
			BufferedReader target = new BufferedReader(new FileReader(targetFile));

			int lineno = 1;
			String actualLine = null;
			String targetLine = null;

			do {
				debug("line number " + lineno);
				actualLine = actual.readLine();
				targetLine = target.readLine();
				if (!(actualLine == null || targetLine == null)) {
					Assert.assertEquals(inputFile.getName() + ": difference at line " + lineno,
						targetLine, actualLine);
				}
				++lineno;
			}
			while (actualLine != null && targetLine != null);
			if (actualLine != null) {
				Assert.assertEquals(inputFile.getName() + ": extra line " + lineno + " at end",
					targetLine, actualLine);
			}
			if (targetLine != null) {
				Assert.assertEquals(inputFile.getName() + ": missing line " + lineno + " at end",
					targetLine, actualLine);
			}

			target.close();
		}
	}

	private void debug(BufferedReader input, BufferedReader actual, BufferedReader target)
			throws IOException {
		String iline;
		String tline;
		String aline;
		int line = 1;
		debug("#:INPUT:TARGET:ACTUAL:");
		do {
			iline = input.readLine();
			tline = target.readLine();
			aline = actual.readLine();
			String accum = line + ":" + iline + ":" + tline + ":" + aline + ":";
			if (aline != null && !aline.equals(tline)) {
				accum +=
					"    *********************************************************************";
			}
			debug(accum);
			++line;
		}
		while (!(iline == null && tline == null && aline == null));
		debug("(END)");
	}

	private List<File> getFiles(final String suffix) {
		String modulePath = Application.getMyModuleRootDirectory().toString();

		List<File> files = new ArrayList<>();
		Set<URL> resources = ResourceManager.getResources(".", suffix);
		for (URL url : resources) {
			if ("file".equals(url.getProtocol()) && url.getPath().startsWith(modulePath)) {
				files.add(new File(url.getPath()));
			}
		}

		Collections.sort(files);
		return files;
	}

	private List<File> getInputFiles() {
		return getFiles(".input");
	}

	private List<File> getTargetFiles() {
		return getFiles(".output");
	}
}
