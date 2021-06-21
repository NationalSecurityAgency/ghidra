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
package agent.gdb.pty.linux;

import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.file.Paths;
import java.util.*;

import agent.gdb.pty.PtyChild;
import agent.gdb.pty.PtySession;
import agent.gdb.pty.local.LocalProcessPtySession;

public class LinuxPtyChild extends LinuxPtyEndpoint implements PtyChild {
	private final String name;

	LinuxPtyChild(int fd, String name) {
		super(fd);
		this.name = name;
	}

	@Override
	public String nullSession() {
		return name;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote This uses {@link ProcessBuilder} to launch the subprocess. See its documentation
	 *           for more details of the parameters of this method.
	 * @implNote This actually launches a special "leader" subprocess, which sets up the session and
	 *           then executes the requested program. The requested program image replaces the
	 *           leader so that the returned process is indeed a handle to the requested program.
	 *           Ordinarily, this does not matter, but it may be useful to know when debugging.
	 *           Furthermore, if special characters are sent on the parent before the image is
	 *           replaced, they may be received by the leader instead. For example, Ctrl-C might be
	 *           received by the leader by mistake if sent immediately upon spawning a new session.
	 *           Users should send a simple command, e.g., "echo", to confirm that the requested
	 *           program is active before sending special characters.
	 * 
	 * @param args the image path and arguments
	 * @param env the environment
	 * @return a handle to the subprocess
	 * @throws IOException
	 */
	@Override
	public PtySession session(String[] args, Map<String, String> env) throws IOException {
		return sessionUsingJavaLeader(args, env);
	}

	protected PtySession sessionUsingJavaLeader(String[] args, Map<String, String> env)
			throws IOException {
		final List<String> argsList = new ArrayList<>();
		argsList.add("java");
		argsList.add("-cp");
		argsList.add(System.getProperty("java.class.path"));
		argsList.add(LinuxPtySessionLeader.class.getCanonicalName());

		argsList.add(name);
		argsList.addAll(Arrays.asList(args));
		ProcessBuilder builder = new ProcessBuilder(argsList);
		if (env != null) {
			builder.environment().putAll(env);
		}
		builder.inheritIO();

		return new LocalProcessPtySession(builder.start());
	}

	protected PtySession sessionUsingPythonLeader(String[] args, Map<String, String> env)
			throws IOException {
		final List<String> argsList = new ArrayList<>();
		argsList.add("python");
		argsList.add("-m");
		argsList.add("session");

		argsList.add(name);
		argsList.addAll(Arrays.asList(args));
		ProcessBuilder builder = new ProcessBuilder(argsList);
		if (env != null) {
			builder.environment().putAll(env);
		}
		String sourceLoc = getSourceLocationForResource("session.py").getAbsolutePath();
		//System.err.println("PYTHONPATH=" + sourceLoc);
		builder.environment().put("PYTHONPATH", sourceLoc);
		builder.inheritIO();

		return new LocalProcessPtySession(builder.start());
	}

	public static File getSourceLocationForResource(String name) {
		// TODO: Refactor this with SystemUtilities.getSourceLocationForClass()
		URL url = LinuxPtyChild.class.getClassLoader().getResource(name);
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
