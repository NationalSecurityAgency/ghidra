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
package agent.dbgmodel;

import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinNT.HANDLE;

public class DummyProc implements AutoCloseable {
	final Process process;
	public final int pid;

	public DummyProc(String... args) throws IOException, NoSuchFieldException, SecurityException,
			IllegalArgumentException, IllegalAccessException {
		process = new ProcessBuilder(args).start();

		Class<? extends Process> cls = process.getClass();
		assumeTrue(cls.getName().equals("java.lang.ProcessImpl"));
		Field handleFld = cls.getDeclaredField("handle");
		handleFld.setAccessible(true);
		long handle = handleFld.getLong(process);
		pid = Kernel32.INSTANCE.GetProcessId(new HANDLE(new Pointer(handle)));
	}

	@Override
	public void close() throws Exception {
		if (!process.destroyForcibly().waitFor(1000, TimeUnit.MILLISECONDS)) {
			throw new TimeoutException("Could not terminate process " + pid);
		}
	}
}
