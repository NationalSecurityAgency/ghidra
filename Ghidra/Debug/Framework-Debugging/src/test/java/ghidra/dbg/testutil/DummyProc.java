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
import java.lang.reflect.Field;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import ghidra.framework.Application;

public class DummyProc implements AutoCloseable {
	final Process process;
	public final long pid;

	public static String which(String cmd) {
		try {
			return Application.getOSFile(cmd).getAbsolutePath();
		}
		catch (Exception e) {
			// fallback to system
		}
		try {
			Process exec = new ProcessBuilder("which", cmd).start();
			exec.waitFor();
			BufferedReader reader =
				new BufferedReader(new InputStreamReader(exec.getInputStream()));
			return reader.readLine().trim();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static DummyProc run(String... args) throws NoSuchFieldException, SecurityException,
			IllegalArgumentException, IllegalAccessException, IOException {
		DummyProc proc = new DummyProc(args);
		return proc;
	}

	DummyProc(String... args) throws IOException, NoSuchFieldException, SecurityException,
			IllegalArgumentException, IllegalAccessException {
		args[0] = which(args[0]);
		process = new ProcessBuilder(args).start();

		@SuppressWarnings("hiding")
		long pid = -1;
		try {
			Field pidFld = process.getClass().getDeclaredField("pid");
			pidFld.setAccessible(true);
			pid = pidFld.getLong(process);
		}
		catch (NoSuchFieldException | SecurityException e) {
			throw new AssertionError("Could not get pid for DummyProc", e);
		}
		this.pid = pid;
	}

	@Override
	public void close() throws Exception {
		if (!process.destroyForcibly().waitFor(1000, TimeUnit.MILLISECONDS)) {
			throw new TimeoutException("Could not terminate process " + pid);
		}
	}
}
