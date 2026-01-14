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

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;

public class SleighLanguageProviderTest extends AbstractGenericTest {

	private LanguageID x86LangId = new LanguageID("x86:LE:32:default");
	private ResourceFile x86LdefsFile = Application.findDataFileInAnyModule("languages/x86.ldefs");
	private SleighLanguageProvider langProvider;


	@Test(timeout = 60000 + 5000 /* 1 minute (default lock timeout) + 5 seconds */)
	public void testSlaThunderingHerds() throws Exception {
		// Tests when a thundering herd of processes all try to read a sleigh file at the same time
		
		langProvider = new SleighLanguageProvider(x86LdefsFile);

		// Ensure the lang file exist, and then tweak the timestamp to force one of the
		// spawned procs to recompile the sla
		SleighLanguage lang = langProvider.getLanguage(x86LangId, TaskMonitor.DUMMY);
		SleighLanguageDescription langDesc = lang.getLanguageDescription();
		SleighLanguageFile langFile = langDesc.getLanguageFile();
		File slaFile = langFile.getSlaFile().getFile(false);
		File slaSpecFile = langFile.getSlaSpecFile().getFile(false);
		slaFile.setLastModified(slaSpecFile.lastModified() - 60 * 1000);

		int procsToStart = 20;
		long langProviderTimeout = SleighLanguageProvider.LANGUAGE_LOCK_TIMEOUT.toMillis();
		long test_start = System.currentTimeMillis();

		// 1) start a lot of processes
		// 2) wait until they initialize themselves and get to step1 (they wait also for next step)
		// 3) allow all launched processes to proceed at same time
		// 4) wait for all to exit with success exit code
		List<TestProc> procs = new ArrayList<>();
		for (int procNum = 0; procNum < procsToStart; procNum++) {
			procs.add(TestProc.start(procNum, langProviderTimeout));
		}

		for (TestProc testProc : procs) {
			if (!testProc.waitUntilStep(1)) {
				fail(testProc.msg("failed to reach step1"));
			}
		}

		// If the spawned processes are writing to the .sla file incorrectly and simultaneously,
		// giving a small delay between each process's critical action historically help expose 
		// the error. 
		int DELAY_BETWEEN_PROCESSES = 600;
		for (TestProc testProc : procs) {
			testProc.sendGoahead();
			sleep(DELAY_BETWEEN_PROCESSES);
		}

		int badExitCount = 0;
		for (TestProc testProc : procs) {
			if (!testProc.waitUntilStep(2)) {
				testProc.log("exited before step 2 reached");
				badExitCount++;
			}
			int exitCode = testProc.proc.waitFor();
			if (exitCode != 0) {
				testProc.log("exited with error: %d".formatted(exitCode));
				badExitCount++;
			}
		}

		Msg.info(this, "Total test time: " + (System.currentTimeMillis() - test_start));

		assertTrue(badExitCount == 0);
	}

	@Test(timeout = 10000 + 5000 /* shorterTimeout + 5 seconds */)
	public void testSlaLockTimeout() throws Exception {
		// Test that lock timeout successfully causes a failure
		langProvider = new SleighLanguageProvider(x86LdefsFile);
		
		SleighLanguageDescription langDesc = langProvider.getLanguageDescription(x86LangId);
		SleighLanguageFile langFile = langDesc.getLanguageFile();

		long shorterTimeoutMS = Duration.ofSeconds(10).toMillis();

		TestProc testProc = TestProc.start(0, shorterTimeoutMS);
		assertTrue(testProc.waitUntilStep(1));
		langFile.withLock(Duration.ofMillis(10), TaskMonitor.DUMMY, () -> {
			testProc.sendGoahead();
			Thread.sleep(shorterTimeoutMS + 1000); // hold lock while testProc is trying to get it, force it to fail
		});

		testProc.assertExitNum(1);
	}

	public void testSlaLanguage_FromOtherProcess() throws Throwable {
		// this is not a junit test entry point, but instead is what is run
		// in each sub-process launched by each TestProc instance.

		langProvider = new SleighLanguageProvider(x86LdefsFile);
		TestProc.waitForGoahead();
		Language lang = langProvider.getLanguage(x86LangId, TaskMonitor.DUMMY);

		// write via stdout to the parent process, which will handle logging
		System.out.println("STEP 2 Got language %s".formatted(lang));
		System.out.flush();

		System.exit(0);
	}

	public static void main(String[] args) {
		// this is the entry point for the launched TestProcs that will be fighting over 
		// a sleigh language file
		try {
			SleighLanguageProviderTest test = new SleighLanguageProviderTest();
			test.testSlaLanguage_FromOtherProcess();
		}
		catch (Throwable th) {
			// write via stdout to the parent process, which will handle logging
			System.out.println("Exception " + th);
			th.printStackTrace(System.out);
			System.exit(1);
		}
	}

	/**
	 * Handles coordinating an external java process that will be attempting to access a common
	 * sleigh language file.
	 */
	static class TestProc {
		static TestProc start(int procNum, long timeoutMS) throws IOException {
			TestProc testProc = new TestProc();
			testProc.procNum = procNum;
			testProc.proc = new JavaProcessBuilder(SleighLanguageProviderTest.class) // self class's main()
					.addProperty(SystemUtilities.TESTING_PROPERTY, "true")
					.addProperty(SleighLanguageProvider.LANGUAGE_LOCK_TIMEOUT_PROPNAME,
						"" + timeoutMS)
					.withStdoutMonitor(testProc::update)
					.start();
			testProc.log("Started");
			return testProc;
		}

		Process proc;
		int procNum;
		AtomicInteger stepNum = new AtomicInteger();
		AtomicBoolean stdoutMonitorDone = new AtomicBoolean();
		Thread monitorThread;

		void sendGoahead() throws IOException {
			proc.getOutputStream().write('\n');
			proc.getOutputStream().flush();
		}

		static void waitForGoahead() throws IOException {
			// write via stdout to the parent process, which will handle logging
			System.out.println("STEP 1 Waiting for synchronization go-ahead...");
			System.out.flush();
			int b = System.in.read();
			System.out.println("Read byte: " + b);
			System.out.flush();
		}

		boolean waitUntilStep(int waitForStepNum) throws InterruptedException {
			while (stepNum.get() < waitForStepNum) {
				if (stdoutMonitorDone.get()) {
					return false;
				}
				Thread.sleep(200);
			}
			return true;
		}

		void update(String s) {
			if (s == null) {
				stdoutMonitorDone.set(true);
				return;
			}
			log(s);
			if (s.startsWith("STEP ")) {
				stepNum.set(Integer.parseInt(s.split(" ")[1]));
			}
		}

		void assertExitNum(int exitNum) throws InterruptedException {
			assertEquals(exitNum, proc.waitFor()); // wait until helper process has finished
			log("exit code: " + proc.waitFor());
		}

		String msg(String s) {
			return "TestProc[%d-%d] %s".formatted(procNum, proc.pid(), s);
		}

		void log(String s) {
			Msg.info(this, msg(s));
		}
	}

}
