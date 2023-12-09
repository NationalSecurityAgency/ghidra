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
package ghidra.pty.linux;

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.pty.PtyChild;
import ghidra.pty.PtySession;
import ghidra.pty.linux.PosixC.Termios;
import ghidra.pty.local.LocalProcessPtySession;
import ghidra.util.Msg;

public class LinuxPtyChild extends LinuxPtyEndpoint implements PtyChild {
	static final PosixC LIB_POSIX = PosixC.INSTANCE;

	private final String name;

	LinuxPtyChild(int fd, String name) {
		super(fd);
		this.name = name;
	}

	@Override
	public String nullSession(Collection<TermMode> mode) {
		applyMode(mode);
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
	 */
	@Override
	public PtySession session(String[] args, Map<String, String> env, File workingDirectory,
			Collection<TermMode> mode) throws IOException {
		return sessionUsingJavaLeader(args, env, workingDirectory, mode);
	}

	protected PtySession sessionUsingJavaLeader(String[] args, Map<String, String> env,
			File workingDirectory, Collection<TermMode> mode) throws IOException {
		final List<String> argsList = new ArrayList<>();
		String javaCommand =
			System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
		argsList.add(javaCommand);
		argsList.add("-cp");
		argsList.add(System.getProperty("java.class.path"));
		argsList.add(LinuxPtySessionLeader.class.getCanonicalName());

		argsList.add(name);
		argsList.addAll(Arrays.asList(args));
		ProcessBuilder builder = new ProcessBuilder(argsList);
		if (env != null) {
			builder.environment().putAll(env);
		}
		if (workingDirectory != null) {
			builder.directory(workingDirectory);
		}
		builder.inheritIO();

		applyMode(mode);

		try {
			return new LocalProcessPtySession(builder.start(), name);
		}
		catch (Exception e) {
			Msg.error(this, "Could not start process with args " + Arrays.toString(args), e);
			throw e;
		}
	}

	private void applyMode(Collection<TermMode> mode) {
		if (mode.contains(Echo.OFF)) {
			disableEcho();
		}
	}

	private void disableEcho() {
		Termios.ByReference tmios = new Termios.ByReference();
		LIB_POSIX.tcgetattr(fd, tmios);
		tmios.c_lflag &= ~Termios.ECHO;
		LIB_POSIX.tcsetattr(fd, Termios.TCSANOW, tmios);
	}
}
