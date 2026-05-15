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
package ghidra.app.plugin.processors.sleigh;

import java.time.Duration;

import org.junit.Test;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.task.TaskMonitor;

public class X86SleighLanguageLockerTest {

	private LanguageID x86LangId = new LanguageID("x86:LE:32:default");

	//@Test
	public void testLockLanguageForever() throws Exception {
		// Locks the language's file forever, for manually testing the GUI frontend when it tries
		// to load a language.
		// This test should not be enabled by default.

		// Don't use a test application config because we need to use the same user specific
		// .ghidra/.ghidra-ver config directories
		Application.initializeApplication(new GhidraApplicationLayout(),
			new ApplicationConfiguration());

		ResourceFile x86LdefsFile = Application.findDataFileInAnyModule("languages/x86.ldefs");
		SleighLanguageProvider langProvider = new SleighLanguageProvider(x86LdefsFile);

		SleighLanguageDescription langDesc = langProvider.getLanguageDescription(x86LangId);
		SleighLanguageFile langFile = langDesc.getLanguageFile();
		// we are reading from stdin, so should use stdout to prompt the user
		System.out.println("Locking lang file: " + langFile.getSlaFile());

		langFile.withLock(Duration.ofMillis(10), TaskMonitor.DUMMY, () -> {
			System.out.println("Press enter to end lock");
			System.in.read(); // if user hits enter in the console of the test, will exit
		});
	}

}
