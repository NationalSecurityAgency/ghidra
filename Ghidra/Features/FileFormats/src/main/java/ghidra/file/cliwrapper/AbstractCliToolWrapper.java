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
package ghidra.file.cliwrapper;

import java.io.*;
import java.lang.ProcessBuilder.Redirect;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;

import org.apache.commons.io.FilenameUtils;

import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.framework.OperatingSystem;
import ghidra.util.Msg;
import ghidra.util.task.*;

/**
 * Base class for common cli tool handling logic
 */
public abstract class AbstractCliToolWrapper implements CliToolWrapper {
	/**
	 * Searches directories specified in the operating system's PATH env var for the specified
	 * executable name.
	 * 
	 * @param name executable file name to find
	 * @return file path of found executable, or {@code null} if not found
	 */
	public static File findInOSPathEnv(String name) {
		for (String pathEntry : System.getenv("PATH").split(File.pathSeparator)) {
			try {
				File pathDir = new File(pathEntry);
				File testFile = normalizeExecutablePath(new File(pathDir, name));
				if (testFile != null) {
					return testFile;
				}
			}
			catch (IOException e) {
				// ignore, try next
			}
		}
		return null;
	}

	/**
	 * Fixes an executable name to conform to the current operating system's naming rules. (add
	 * ".exe" to windows exe's)
	 * 
	 * @param f executable filename
	 * @return updated executable filename
	 * @throws IOException if error resolving filename
	 */
	public static File normalizeExecutablePath(File f) throws IOException {
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS &&
			!FilenameUtils.getExtension(f.getName()).equals("exe")) {
			f = new File(f.getParentFile(), f.getName() + ".exe");
		}
		return f.isFile() ? f.getCanonicalFile() : null;
	}

	/**
	 * Searches the directories specified in the operating system's PATH env var for an executable
	 * that matches one of the specified names, and also passes the 
	 * {@link CliToolWrapper#isValid(TaskMonitor)} test.
	 * 
	 * @param <T> specific CliToolWrapper type
	 * @param exeNames list of executable names
	 * @param monitor {@link TaskMonitor}
	 * @param toolCreator creates instance of the cli tool wrapper (eg. MyCliToolWrapper::new)
	 * @return new cli tool wrapper instance, or {@code null} if none are found or none pass the
	 * isValid() check
	 */
	public static <T extends AbstractCliToolWrapper> T findToolWrapper(List<String> exeNames,
			TaskMonitor monitor, Function<File, T> toolCreator) {
		for (String exeName : exeNames) {
			File exeFile = findInOSPathEnv(exeName);
			if (exeFile != null) {
				T tmp = toolCreator.apply(exeFile);
				if (tmp.isValid(monitor)) {
					return tmp;
				}
			}
		}
		return null;
	}

	private final static long DEFAULT_TIMEOUT_MS = 5000;

	protected long timeoutMS = DEFAULT_TIMEOUT_MS;
	protected File nativeExecutable;

	protected AbstractCliToolWrapper(File nativeExecutable) {
		this.nativeExecutable = nativeExecutable;
	}

	protected List<String> getCmdLine(List<String> args) {
		List<String> cmdLine = new ArrayList<>(args.size() + 1);
		cmdLine.add(nativeExecutable.getPath());
		cmdLine.addAll(args);
		return cmdLine;
	}

	protected int execAndReadStdOut(List<String> args, TaskMonitor monitor,
			Consumer<String> stdoutConsumer) throws IOException {

		List<String> cmd = getCmdLine(args);
		Process process = new ProcessBuilder(cmd).redirectError(Redirect.DISCARD).start();
		process.getOutputStream().close();
		CancelledListener l = () -> process.destroyForcibly();

		try {
			monitor.addCancelledListener(l);
			BufferedReader inputReader = process.inputReader();
			String line;
			while (!monitor.isCancelled() && (line = inputReader.readLine()) != null) {
				stdoutConsumer.accept(line);
			}

			if (!monitor.isCancelled() && process.waitFor(timeoutMS, TimeUnit.MILLISECONDS)) {
				return process.exitValue();
			}
			process.destroyForcibly();
			throw new IOException("Process %s timeout".formatted(cmd));
		}
		catch (InterruptedException e) {
			throw new IOException(e);
		}
		finally {
			monitor.removeCancelledListener(l);
		}
	}

	protected int execAndRedirectStdOut(List<String> args, InputStream is, OutputStream os,
			TaskMonitor monitor) throws IOException {
		TaskMonitor upwtm = new UnknownProgressWrappingTaskMonitor(monitor);

		List<String> cmd = getCmdLine(args);
		Process process = new ProcessBuilder(cmd).redirectError(Redirect.DISCARD).start();
		CancelledListener l = () -> process.destroyForcibly();

		try {
			monitor.addCancelledListener(l);

			if (is != null) {
				OutputStream processStdin = process.getOutputStream();
				Thread stdinThread = new Thread(() -> {
					byte[] buffer = new byte[1024 * 64];
					int bytesRead;
					try {
						while (!upwtm.isCancelled() && (bytesRead = is.read(buffer)) > 0) {
							processStdin.write(buffer, 0, bytesRead);
						}
						processStdin.flush();
					}
					catch (IOException e) {
						Msg.error(AbstractCliToolWrapper.this, "Error streaming to tool stdin", e);
					}
					finally {
						FSUtilities.uncheckedClose(processStdin, null);
					}
				}, nativeExecutable.getName() + " stdin stream");
				stdinThread.setDaemon(true);
				stdinThread.start();
			}

			InputStream processStdout = process.getInputStream();
			byte[] buffer = new byte[1024 * 64];
			int bytesRead;
			long totalBytesRead = 0;
			while (!monitor.isCancelled() && (bytesRead = processStdout.read(buffer)) > 0) {
				os.write(buffer, 0, bytesRead);
				totalBytesRead += bytesRead;
				upwtm.setProgress(totalBytesRead);
			}
		}
		finally {
			monitor.removeCancelledListener(l);
		}

		try {
			if (!monitor.isCancelled() && process.waitFor(timeoutMS, TimeUnit.MILLISECONDS)) {
				return process.exitValue();
			}

			process.destroyForcibly();
			throw new IOException("Process %s timeout".formatted(cmd));
		}
		catch (InterruptedException e) {
			throw new IOException(e);
		}
	}

}
