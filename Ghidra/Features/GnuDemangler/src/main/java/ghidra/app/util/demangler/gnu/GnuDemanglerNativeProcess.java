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
import java.nio.charset.Charset;
import java.util.*;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

import ghidra.framework.Application;
import ghidra.framework.Platform;

/**
 * A class that allows for the reuse of native demangler executable processes.  This class will
 * cache the process by name and by any arguments passed to the process when started.  Once
 * successfully started, the process will persist
 */
public class GnuDemanglerNativeProcess {
	public static final String DEMANGLER_GNU = GnuDemanglerOptions.GNU_DEMANGLER_DEFAULT;

	private static final String DEFAULT_NATIVE_OPTIONS = "";
	private static final Map<String, GnuDemanglerNativeProcess> processesByName =
		new HashMap<>();

	private String applicationName;
	private String options;

	private boolean isDisposed;
	private Process process;
	private BufferedReader reader;
	private PrintWriter writer;

	/**
	 * Gets the default GNU demangler native process
	 * @return the process
	 * @throws IOException if the process cannot be started
	 */
	public static synchronized GnuDemanglerNativeProcess getDemanglerNativeProcess()
			throws IOException {
		return getDemanglerNativeProcess(DEMANGLER_GNU);
	}

	/**
	 * Gets the default GNU demangler native process
	 * @param name the specific executable name to launch
	 * @return the process
	 * @throws IOException if the process cannot be started
	 */
	public static synchronized GnuDemanglerNativeProcess getDemanglerNativeProcess(String name)
			throws IOException {

		return getDemanglerNativeProcess(name, DEFAULT_NATIVE_OPTIONS);
	}

	/**
	 * Gets the default GNU demangler native process
	 * @param name the specific executable name to launch
	 * @param nativeOptions the arguments string to pass to the native demangler
	 * @return the process
	 * @throws IOException if the process cannot be started
	 */
	public static synchronized GnuDemanglerNativeProcess getDemanglerNativeProcess(String name,
			String nativeOptions)
			throws IOException {

		String options = nativeOptions;
		if (StringUtils.isBlank(options)) {
			options = DEFAULT_NATIVE_OPTIONS;
		}

		String key = getKey(name, options);
		GnuDemanglerNativeProcess nativeProcess = processesByName.get(key);
		if (nativeProcess == null) {
			nativeProcess = new GnuDemanglerNativeProcess(name, options);
		}
		return nativeProcess;
	}

	private static String getKey(String name, String options) {
		return name + ' ' + options;
	}

	private GnuDemanglerNativeProcess(String applicationName, String options) throws IOException {
		this.applicationName = applicationName;
		this.options = options;
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
			return doDemangle(mangled);
		}
		catch (IOException e) {
			dispose();
			if (!restart) {
				throw new IOException("Demangler process is not running.", e);
			}
			createProcess();
			return demangle(mangled, false);
		}
	}

	private String doDemangle(String mangled) throws IOException {
		writer.println(mangled);
		writer.flush();
		return reader.readLine();
	}

	public void dispose() {

		String key = getKey(applicationName, options);
		processesByName.remove(key);

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

		String[] command = buildCommand();
		process = Runtime.getRuntime().exec(command);

		InputStream in = process.getInputStream();
		OutputStream out = process.getOutputStream();
		reader = new BufferedReader(new InputStreamReader(in));
		writer = new PrintWriter(out);

		checkForError(command);

		isDisposed = false;
		String key = getKey(applicationName, options);
		processesByName.put(key, this);
	}

	private String[] buildCommand() throws FileNotFoundException {

		String executableName =
			applicationName + Platform.CURRENT_PLATFORM.getExecutableExtension();
		File commandPath = Application.getOSFile(executableName);

		String[] command = new String[] { commandPath.getAbsolutePath() };
		if (!StringUtils.isBlank(options)) {
			String[] optionsArray = options.split("\\s");
			command = ArrayUtils.addAll(command, optionsArray);
		}
		return command;
	}

	private void checkForError(String[] command) throws IOException {

		//
		// We do not want to read the error stream in the happy path case, as that will block.
		// Send a test string over and read the result.   If the test string is blank, then
		// there was an error.
		//
		String testResult = doDemangle("test");
		if (!StringUtils.isBlank(testResult)) {
			return;
		}

		InputStream err = process.getErrorStream();
		String error = null;
		try {
			List<String> errorLines = IOUtils.readLines(err, Charset.defaultCharset());
			error = StringUtils.join(errorLines, '\n');
		}
		catch (IOException e) {
			throw new IOException("Unable to read process error stream: ", e);
		}

		if (StringUtils.isBlank(error)) {
			return;
		}

		String executable = command[0];
		String baseName = FilenameUtils.getBaseName(executable);
		command[0] = baseName;

		// cleanup full path, as it is ugly in the error message
		error = error.replace(executable, "");
		throw new IOException("Error starting demangler with command: '" +
			Arrays.toString(command) + "' " + error);
	}
}
