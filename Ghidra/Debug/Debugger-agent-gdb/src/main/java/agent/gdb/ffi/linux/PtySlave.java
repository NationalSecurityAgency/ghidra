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
package agent.gdb.ffi.linux;

import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.file.Paths;
import java.util.*;

/**
 * The slave end of a pseudo-terminal
 */
public class PtySlave extends PtyEndpoint {
	private final File file;

	PtySlave(int fd, String name) {
		super(fd);
		this.file = new File(name);
	}

	/**
	 * Get the file referring to this pseudo-terminal
	 * 
	 * @return the file
	 */
	public File getFile() {
		return file;
	}

	/**
	 * Spawn a subprocess in a new session whose controlling tty is this pseudo-terminal
	 * 
	 * Implementation note: This uses {@link ProcessBuilder} to launch the subprocess. See its
	 * documentation for more details of the parameters of this method.
	 * 
	 * Deep implementation note: This actually launches a Python script, which sets up the session
	 * and then executes the requested program. The requested program image replaces the Python
	 * interpreter so that the returned process is indeed a handle to the requested program, not a
	 * Python interpreter. Ordinarily, this does not matter, but it may be useful to know when
	 * debugging. Furthermore, if special characters are sent on the master before Python has
	 * executed the requested program, they may be received by the Python interpreter. For example,
	 * Ctrl-C might be received by Python by mistake if sent immediately upon spawning a new
	 * session. Users should send a simple command, e.g., "echo", to confirm that the requested
	 * program is active before sending special characters.
	 * 
	 * @param args the image path and arguments
	 * @param env the environment
	 * @return a handle to the subprocess
	 * @throws IOException
	 */
	public Process session(String[] args, Map<String, String> env) throws IOException {
		return sessionUsingJavaLeader(args, env);
	}

	protected Process sessionUsingJavaLeader(String[] args, Map<String, String> env)
			throws IOException {
		final List<String> argsList = new ArrayList<>();
		argsList.add("java");
		argsList.add("-cp");
		argsList.add(System.getProperty("java.class.path"));
		argsList.add(PtySessionLeader.class.getCanonicalName());

		argsList.add(file.getAbsolutePath());
		argsList.addAll(Arrays.asList(args));
		ProcessBuilder builder = new ProcessBuilder(argsList);
		if (env != null) {
			builder.environment().putAll(env);
		}
		builder.inheritIO();

		return builder.start();
	}

	protected Process sessionUsingPythonLeader(String[] args, Map<String, String> env)
			throws IOException {
		final List<String> argsList = new ArrayList<>();
		argsList.add("python");
		argsList.add("-m");
		argsList.add("session");

		argsList.add(file.getAbsolutePath());
		argsList.addAll(Arrays.asList(args));
		ProcessBuilder builder = new ProcessBuilder(argsList);
		if (env != null) {
			builder.environment().putAll(env);
		}
		String sourceLoc = getSourceLocationForResource("session.py").getAbsolutePath();
		//System.err.println("PYTHONPATH=" + sourceLoc);
		builder.environment().put("PYTHONPATH", sourceLoc);
		builder.inheritIO();

		return builder.start();
	}

	public static File getSourceLocationForResource(String name) {
		// TODO: Refactor this with SystemUtilities.getSourceLocationForClass()
		URL url = PtySlave.class.getClassLoader().getResource(name);
		String urlFile = url.getFile();
		try {
			urlFile = URLDecoder.decode(urlFile, "UTF-8");
		}
		catch (UnsupportedEncodingException e) {
			// can't happen, since we know the encoding is correct
			throw new AssertionError(e);
		}

		if ("file".equals(url.getProtocol())) {
			int packageLevel = Paths.get(name).getNameCount();
			File file = new File(urlFile);
			for (int i = 0; i < packageLevel; i++) {
				file = file.getParentFile();
			}
			return file;
		}

		if ("jar".equals(url.getProtocol())) {
			// Running from Jar file
			String jarPath = urlFile;
			if (!jarPath.startsWith("file:")) {
				return null;
			}

			// strip off the 'file:' prefix and the jar path suffix after the
			// '!'
			jarPath = jarPath.substring(5, jarPath.indexOf('!'));
			return new File(jarPath);
		}

		return null;
	}
}
