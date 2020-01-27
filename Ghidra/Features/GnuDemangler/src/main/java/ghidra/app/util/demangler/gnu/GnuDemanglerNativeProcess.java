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
package ghidra.app.util.demangler.gnu;

import java.io.*;

import ghidra.framework.Application;
import ghidra.framework.Platform;

public class GnuDemanglerNativeProcess {
	public static final String DEMANGLER_GNU = "demangler_gnu_v2.33.1";

	private static GnuDemanglerNativeProcess demanglerNativeProcess;

	private boolean isDisposed;
	private Process process;
	private BufferedReader reader;
	private PrintWriter writer;

	public static synchronized GnuDemanglerNativeProcess getDemanglerNativeProcess()
			throws IOException {
		if (demanglerNativeProcess == null) {
			demanglerNativeProcess = new GnuDemanglerNativeProcess();
		}
		return demanglerNativeProcess;
	}

	private GnuDemanglerNativeProcess() throws IOException {
		createProcess();
	}

	public synchronized String demangle(String mangled) throws IOException {
		if (isDisposed) {
			throw new IOException("Demangled process has been terminated.");
		}
		return demangle(mangled, true);
	}

	private String demangle(String mangled, boolean restart) throws IOException {
		try {
			writer.println(mangled);
			writer.flush();

			return reader.readLine();
		}
		catch (IOException e) {
			dispose();
			if (!restart) {
				demanglerNativeProcess = null;
				throw new IOException("Demangler process is not running.");
			}
			createProcess();
			return demangle(mangled, false);
		}
	}

	private void dispose() {
		try {
			if (process != null) {
				process.destroy();
			}
			process = null;
			reader = null;
			writer = null;
		}
		catch (Exception e) {
			// ignore
		}
		finally {
			isDisposed = true;
		}
	}

	private void createProcess() throws IOException {

		String executableName = DEMANGLER_GNU + Platform.CURRENT_PLATFORM.getExecutableExtension();
		File commandPath = Application.getOSFile(executableName);

		String[] command = new String[] { commandPath.getAbsolutePath() };

		process = Runtime.getRuntime().exec(command);

		InputStream in = process.getInputStream();
		OutputStream out = process.getOutputStream();

		reader = new BufferedReader(new InputStreamReader(in));
		writer = new PrintWriter(out);

		isDisposed = false;
	}
}
