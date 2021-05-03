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
package ghidra.dbg.testutil;

import java.io.*;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import ghidra.framework.Application;
import ghidra.util.Msg;

public class DummyProc implements AutoCloseable {
	public final Process process;
	public final long pid;

	public static String which(String cmd) {
		try {
			return Application.getOSFile(cmd).getAbsolutePath();
		}
		catch (Exception e) {
			// fallback to system
		}
		if (new File(cmd).canExecute()) {
			return cmd;
		}
		String line;
		try {
			boolean isWindows = System.getProperty("os.name").toLowerCase().contains("windows");
			Process exec = new ProcessBuilder(isWindows ? "where" : "which", cmd).start();
			exec.waitFor();
			BufferedReader reader =
				new BufferedReader(new InputStreamReader(exec.getInputStream()));
			line = reader.readLine();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		if (line == null) {
			throw new RuntimeException("Cannot find " + cmd);
		}
		return line.trim();
	}

	public static DummyProc run(String... args) throws IOException {
		DummyProc proc = new DummyProc(args);
		return proc;
	}

	DummyProc(String... args) throws IOException {
		args[0] = which(args[0]);
		process = new ProcessBuilder(args)
				.inheritIO()
				.start();

		pid = process.pid();
		Msg.info(this, "Started dummy process pid = " + pid + ": " + List.of(args));
	}

	@Override
	public void close() throws Exception {
		if (!process.destroyForcibly().waitFor(1000, TimeUnit.MILLISECONDS)) {
			Msg.error(this, "Could not terminate process " + pid);
			throw new TimeoutException("Could not terminate process " + pid);
		}
	}
}
