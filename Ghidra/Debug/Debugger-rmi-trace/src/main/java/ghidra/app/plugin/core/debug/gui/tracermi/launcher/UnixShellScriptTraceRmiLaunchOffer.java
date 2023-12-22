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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.SocketAddress;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.debug.gui.tracermi.launcher.ScriptAttributesParser.ScriptAttributes;
import ghidra.program.model.listing.Program;

/**
 * A launcher implemented by a simple UNIX shell script.
 * 
 * <p>
 * The script must start with an attributes header in a comment block. See
 * {@link ScriptAttributesParser}.
 */
public class UnixShellScriptTraceRmiLaunchOffer extends AbstractScriptTraceRmiLaunchOffer {
	public static final String SHEBANG = "#!";

	/**
	 * Create a launch offer from the given shell script.
	 * 
	 * @param program the current program, usually the target image. In general, this should be used
	 *            for at least two purposes. 1) To populate the default command line. 2) To ensure
	 *            the target image is mapped in the resulting target trace.
	 * @throws FileNotFoundException
	 */
	public static UnixShellScriptTraceRmiLaunchOffer create(TraceRmiLauncherServicePlugin plugin,
			Program program, File script) throws FileNotFoundException {
		ScriptAttributesParser parser = new ScriptAttributesParser() {
			@Override
			protected boolean ignoreLine(int lineNo, String line) {
				return line.isBlank() || line.startsWith(SHEBANG) && lineNo == 1;
			}

			@Override
			protected String removeDelimiter(String line) {
				String stripped = line.stripLeading();
				if (!stripped.startsWith("#")) {
					return null;
				}
				return stripped.substring(1);
			}
		};
		ScriptAttributes attrs = parser.parseFile(script);
		return new UnixShellScriptTraceRmiLaunchOffer(plugin, program, script,
			"UNIX_SHELL:" + script.getName(), attrs);
	}

	private UnixShellScriptTraceRmiLaunchOffer(TraceRmiLauncherServicePlugin plugin,
			Program program,
			File script, String configName, ScriptAttributes attrs) {
		super(plugin, program, script, configName, attrs);
	}

	@Override
	protected void prepareSubprocess(List<String> commandLine, Map<String, String> env,
			Map<String, ?> args, SocketAddress address) {
		ScriptAttributesParser.processArguments(commandLine, env, script, attrs.parameters(), args,
			address);
	}
}
