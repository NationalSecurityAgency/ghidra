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
package ghidra.file.formats.ios.dmg;

import java.io.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.SynchronousQueue;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.timer.Watchdog;
import utilities.util.FileUtilities;

/**
 * Manages the DMG server process and communication with it.
 * <p>
 * All IO to the server process takes place in a single background worker thread
 * (see {@link #processManagerLoop()}) that receives {@link Cmd commands} from
 * other threads via a {@link #cmdQueue queue}, writes the cmd to the stdin of
 * the server process, and then reads the responses from its stdout, and then
 * packages up the response and notifies the waiting caller thread that the
 * results are ready.
 * <p>
 * This ensures that there are no synchronous issues with communicating with the
 * server process and that the logic to restart the server if it fails is all in
 * one place.
 * <p>
 * A {@link Watchdog} implementation is used to force timeouts on IO operations
 * by killing the server process.
 */
class DmgServerProcessManager implements Closeable {

	public static final String DMG_MODULE_NAME = "DMG";
	private static final int MIN_DMG_SERVER_MEMORY_MB = 100;

	private File file;
	private Process process = null;
	private Thread cmdThread;
	private SynchronousQueue<Cmd> cmdQueue = new SynchronousQueue<>();

	private int dmgServerMemoryMB;
	private int cmdCount;
	private int dmgServerMaxCmdPerSession = 25000;
	private int dmgCmdTimeoutMS = 20 * 1000;
	private Watchdog watchdog = new Watchdog(dmgCmdTimeoutMS, this::timeoutMethod);
	private String logPrefix;

	DmgServerProcessManager(File file, String logPrefix) {
		this.file = file;
		this.logPrefix = logPrefix;

		dmgServerMemoryMB = readDMGServerMemoryConfigValue(1024);
		cmdThread = new Thread(this::processManagerLoop, "DMG client/server command loop");
		cmdThread.start();
	}

	public void setDMGServerMemoryMB(int mb) {
		this.dmgServerMemoryMB = mb;
	}

	@Override
	public void close() throws IOException {
		Msg.info(this, "Shutting down DMG server");
		sendCmd(null, 0);
	}

	public void interruptCmd() {
		timeoutMethod();
	}

	private void timeoutMethod() {
		Process localProcess = process;
		if (localProcess != null && localProcess.isAlive()) {
			localProcess.destroy();
		}
	}

	private void processManagerLoop() {
		while (true) {
			if (cmdCount == 0) {
				Msg.debug(this, "Starting new DMG server process");
			}
			else {
				Msg.debug(this, "Re-starting DMG server process, cmd count: " + cmdCount);
			}
			this.process = createProcess();
			if (process == null) {
				Msg.error(this, "Failed to create new DMG server process, exiting cmd loop");
				return;
			}

			BufferedReader inputReader =
				new BufferedReader(new InputStreamReader(process.getInputStream()));
			PrintWriter outputWriter = new PrintWriter(process.getOutputStream());
			startReaderThread(new BufferedReader(new InputStreamReader(process.getErrorStream())));

			// hack to send the inital "open" to the dmg server process
			Cmd startupCmd = new Cmd("open " + file.getAbsolutePath(), 0);

			try {
				while (++cmdCount % dmgServerMaxCmdPerSession != 0) {
					Cmd cmd = (startupCmd != null) ? startupCmd : cmdQueue.take();
					startupCmd = null;

					synchronized (cmd) {
						try {
							if (cmd.cmdStr != null) {
								watchdog.arm();
								outputWriter.println(cmd.cmdStr);
								outputWriter.flush();

								int expectedResponseCount = cmd.expectedResponseCount;
								if (expectedResponseCount == Cmd.UNKNOWN_RESPONSE_COUNT) {
									expectedResponseCount = readInt(inputReader);
								}
								else if (expectedResponseCount < 0) {
									int nestedResponseCount = -expectedResponseCount;
									expectedResponseCount =
										readInt(inputReader) * nestedResponseCount;
								}
								cmd.results = new ArrayList<>(expectedResponseCount);
								for (int i = 0; i < expectedResponseCount; i++) {
									String s = inputReader.readLine();
									if (s == null) {
										throw new IOException(
											"EOF while reading results from DMG Server");
									}
									cmd.results.add(s);
								}
							}
						}
						catch (IOException ioe) {
							cmd.error = ioe;
							break;// break cmd loop, destroy process and start a new one
						}
						finally {
							watchdog.disarm();
							cmd.notifyAll();
						}
					}
					if (cmd.cmdStr == null) {
						return;// shutdown, exit entire cmd loop
					}
				}
			}
			catch (InterruptedException ie) {
				Msg.error(this, "IntrError", ie);
				return;// shutdown the server processing loop
			}
			finally {
				Msg.info(this, "DMG server process destroyed");
				process.destroy();
				try {
					int exitCode = process.waitFor();
					Msg.debug(this, "DMG Server process exited with: " + exitCode);
				}
				catch (InterruptedException e) {
					// ignore
				}
				process = null;
			}
		}
	}

	/**
	 * Sends a command to the DMG server process.
	 * <p>
	 * ExpectedResults can be positive (ie. N result lines will be read from the
	 * server process),
	 * <li>0 (no result lines will be read),
	 * <li>{@link Cmd#UNKNOWN_RESPONSE_COUNT UNKNOWN_RESPONSE_COUNT} const value
	 * that indicates that the first response from the command will be the
	 * number of following lines,
	 * <li>or negative, meaning that an variable number of responses of size
	 * abs(N) will be read from the server, where the first response from the
	 * command is the variable number. In all, abs(N) * (first_response_int)
	 * will be the total number of result lines returned.
	 *
	 * @param cmdStr
	 * @param expectedResults
	 * @return
	 * @throws IOException
	 */
	public List<String> sendCmd(String cmdStr, int expectedResults) throws IOException {
		Cmd cmd = new Cmd(cmdStr, expectedResults);

		synchronized (cmd) {
			try {
				cmdQueue.put(cmd);
				cmd.wait(dmgCmdTimeoutMS * 2);
				if (cmd.error != null) {
					throw cmd.error;
				}
				return cmd.results;
			}
			catch (InterruptedException ie) {
				//
			}
		}

		return cmd.results;
	}

	private class Cmd {
		static final int UNKNOWN_RESPONSE_COUNT = Integer.MIN_VALUE;
		String cmdStr;
		int expectedResponseCount;
		List<String> results;
		IOException error;

		Cmd(String cmdStr, int expectedResponseCount) {
			this.cmdStr = cmdStr;
			this.expectedResponseCount = expectedResponseCount;
		}
	}

	private Process createProcess() {
		String classPath = buildClasspath();

		// library path setup
		String envp[] = buildEnvironmentVariables();

		String java =
			System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";

		// optional: -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=18200
		try {
			Process p = Runtime.getRuntime().exec(
				new String[] { java, "-classpath", classPath, "-Xmx" + dmgServerMemoryMB + "m", //need more memory to load and xfer data across pipe
					"mobiledevices.dmg.server.DmgServer" },
				envp, null);
			return p;
		}
		catch (IOException e) {
			Msg.info(this, "Error when creating DMG sever process: ", e);
		}
		return null;
	}

	private String buildClasspath() {
		StringBuilder builder = new StringBuilder();

		ResourceFile dmgModule = Application.getModuleRootDir(DMG_MODULE_NAME);
		ResourceFile standaloneLibDir = new ResourceFile(dmgModule, "data/lib");
		ResourceFile[] standaloneLibs = standaloneLibDir.listFiles();
		for (ResourceFile standaloneLib : standaloneLibs) {
			if (standaloneLib.getName().endsWith(".jar")) {
				File standaloneLibFile = standaloneLib.getFile(true);
				builder.append(standaloneLibFile.getAbsolutePath());
				builder.append(File.pathSeparator);
			}
		}

		if (SystemUtilities.isInDevelopmentMode()) {
			ResourceFile binDirectory = new ResourceFile(dmgModule, "bin/dmg");
			builder.append(binDirectory.getAbsolutePath());
			builder.append(File.pathSeparator);
		}

		return builder.toString();
	}

	private int readDMGServerMemoryConfigValue(int defaultValue) {
		ResourceFile dmgModule = Application.getModuleRootDir(DMG_MODULE_NAME);
		ResourceFile serverMemoryCfgFile = new ResourceFile(dmgModule, "data/server_memory.cfg");
		try {
			List<String> lines = FileUtilities.getLines(serverMemoryCfgFile);
			int result = (lines.size() > 0)
					? Math.max(Integer.parseInt(lines.get(0)), MIN_DMG_SERVER_MEMORY_MB)
					: defaultValue;
			return result;
		}
		catch (NumberFormatException | IOException e) {
			// ignore
		}
		return defaultValue;
	}

	private String[] buildEnvironmentVariables() {
		String pathValue = getLibraryPathVariable("PATH", "");
		String ldLibraryPathValue = getLibraryPathVariable("LD_LIBRARY_PATH", "");

		List<String> argList = new ArrayList<>();
		Map<String, String> env = System.getenv();
		Set<Entry<String, String>> entrySet = env.entrySet();
		for (Entry<String, String> entry : entrySet) {
			if (entry.getKey().equalsIgnoreCase("PATH")) {
				// add our value to the current value
				pathValue = getLibraryPathVariable(entry.getKey(), entry.getValue());
			}
			else if (entry.getKey().equalsIgnoreCase("LD_LIBRARY_PATH")) {
				// add our value to the current value
				ldLibraryPathValue = getLibraryPathVariable(entry.getKey(), entry.getValue());
			}
			else {
				argList.add(entry.getKey() + "=" + entry.getValue());
			}
		}

		// adjust our paths to find custom libraries
		argList.add(pathValue);// for Windows
		argList.add(ldLibraryPathValue);// for Linux

		return argList.toArray(new String[argList.size()]);
	}

	private String getLibraryPathVariable(String pathKey, String pathValue) {
		Set<String> libraryPaths = new HashSet<>();
		addOSPaths(libraryPaths);

		StringBuffer buffy = new StringBuffer();
		buffy.append(pathKey + "=");
		for (String path : libraryPaths) {
			buffy.append(path).append(File.pathSeparator);
		}

		// add in the old path value
		buffy.append(pathValue);

		return buffy.toString();
	}

	private void addOSPaths(Set<String> pathSet) {
		String osFilePath = "data/os/" + Platform.CURRENT_PLATFORM.getDirectoryName();

		ResourceFile module = Application.getModuleRootDir(DMG_MODULE_NAME);
		ResourceFile standaloneOSDir = new ResourceFile(module, osFilePath);
		ResourceFile[] standaloneResourceFiles = standaloneOSDir.listFiles();
		if (standaloneResourceFiles == null) {
			return;
		}
		for (ResourceFile resourceFile : standaloneResourceFiles) {
			File standaloneFile = resourceFile.getFile(true);// copy as needed
			pathSet.add(standaloneFile.getParentFile().getAbsolutePath());
		}
	}

	int readInt(BufferedReader inputReader) throws IOException {
		String s = inputReader.readLine();
		if (s == null) {
			throw new IOException("EOF while reading results from DMG Server");
		}
		try {
			return Integer.parseInt(s);
		}
		catch (NumberFormatException nfe) {
			throw new IOException(
				"Bad data while reading result from DMG Server, expected integer: " + s, nfe);
		}
	}

	private void startReaderThread(BufferedReader reader) {
		new Thread(() -> {
			try {
				while (true) {
					String line = reader.readLine();
					if (line == null) {
						break;
					}
					Msg.info(this, logPrefix + ": " + line);
				}
			}
			catch (IOException ioe) {
				// ignore io errors while reading because thats normal when shutting down
			}
			catch (Exception e) {
				Msg.error(this, "Exception while reading output from DMG process", e);
			}

		}, "DMG Server StdErr Reader Thread").start();
	}
}
