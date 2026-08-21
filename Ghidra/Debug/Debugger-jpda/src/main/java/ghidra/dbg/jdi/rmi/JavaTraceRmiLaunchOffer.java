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
package ghidra.dbg.jdi.rmi;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.SocketAddress;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.plugin.core.debug.gui.tracermi.launcher.*;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.ScriptAttributesParser.ScriptAttributes;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.ScriptAttributesParser.TtyCondition;
import ghidra.dbg.jdi.rmi.jpda.JdiClientThread;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.TerminalSession;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * A launcher implemented by a simple UNIX shell script.
 * 
 * <p>
 * The script must start with an attributes header in a comment block. See
 * {@link ScriptAttributesParser}.
 */
public class JavaTraceRmiLaunchOffer extends AbstractScriptTraceRmiLaunchOffer {
	public static final String REM = "//";
	public static final int REM_LEN = REM.length();

	/**
	 * Create a launch offer from the given shell script.
	 * 
	 * @param plugin the launcher service plugin
	 * @param program the current program, usually the target image. In general, this should be used
	 *            for at least two purposes. 1) To populate the default command line. 2) To ensure
	 *            the target image is mapped in the resulting target trace.
	 * @param script the script file that implements this offer
	 * @return the offer
	 * @throws FileNotFoundException if the script file does not exist
	 */
	public static JavaTraceRmiLaunchOffer create(TraceRmiLauncherServicePlugin plugin,
			Program program, File script) throws FileNotFoundException {
		ScriptAttributesParser parser = new ScriptAttributesParser() {
			@Override
			protected boolean ignoreLine(int lineNo, String line) {
				return line.isBlank();
			}

			@Override
			protected String removeDelimiter(String line) {
				String stripped = line.stripLeading();
				if (!stripped.startsWith(REM)) {
					return null;
				}
				return stripped.substring(REM_LEN);
			}
		};
		ScriptAttributes attrs = parser.parseFile(script);
		return new JavaTraceRmiLaunchOffer(plugin, program, script,
			"JAVA:" + script.getName(), attrs);
	}

	private JavaTraceRmiLaunchOffer(TraceRmiLauncherServicePlugin plugin,
			Program program, File script, String configName, ScriptAttributes attrs) {
		super(plugin, program, script, configName, attrs);
	}

	boolean hasKeyReally(Map<String, String> env, String key) {
		String val = env.get(key);
		return val != null && !val.isBlank();
	}

	@Override
	protected TraceRmiBackEnd launchBackEnd(TaskMonitor monitor,
			Map<String, TerminalSession> sessions, Map<String, ValStr<?>> args,
			SocketAddress address) throws Exception {
		List<String> commandLine = new ArrayList<>();
		Map<String, String> env = new HashMap<>(System.getenv());
		prepareSubprocess(commandLine, env, args, address);

		for (Map.Entry<String, TtyCondition> ent : attrs.extraTtys().entrySet()) {
			if (!ent.getValue().isActive(args)) {
				continue;
			}
			NullPtyTerminalSession ns = nullPtyTerminal();
			env.put(ent.getKey(), ns.name());
			sessions.put(ns.name(), ns);
		}

		TraceRmiBackEnd result = new TraceRmiBackEnd();
		if (hasKeyReally(env, "OPT_JSHELL_PATH")) {
			String classPath = computeClassPath(env);
			commandLine.add(0, "--startup");
			commandLine.add(0, "--class-path=" + classPath);
			commandLine.add(0, env.get("OPT_JSHELL_PATH"));
			PtyTerminalSession session =
				runInTerminal(commandLine, env, script.getParentFile(), sessions.values());
			sessions.put("Shell", session);
			session.terminal().addTerminalListener(result);
		}
		else {
			JdiClientThread thread = new JdiClientThread(env) {
				@Override
				public void run() {
					super.run();
					result.terminated(0);
				}
			};
			thread.start();
		}
		return result;
	}

	private String computeClassPath(Map<String, String> env) {
		String sep = File.pathSeparator;
		return Stream.of(System.getProperty("java.class.path").split(sep))
				.filter(p -> new File(p).exists())
				.collect(Collectors.joining(sep));
	}

	@Override
	public boolean requiresImage() {
		return false;
	}

}
