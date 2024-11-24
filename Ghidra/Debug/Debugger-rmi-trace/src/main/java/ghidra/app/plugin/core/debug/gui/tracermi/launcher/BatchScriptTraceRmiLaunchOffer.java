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
import ghidra.debug.api.ValStr;
import ghidra.program.model.listing.Program;

/**
 * A launcher implemented by a simple DOS/Windows batch file.
 *
 * <p>
 * The script must start with an attributes header in a comment block. See
 * {@link ScriptAttributesParser}.
 */
public class BatchScriptTraceRmiLaunchOffer extends AbstractScriptTraceRmiLaunchOffer {
	public static final String REM = "::";
	public static final int REM_LEN = REM.length();

	/**
	 * Create a launch offer from the given batch file.
	 * 
	 * @param plugin the launcher service plugin
	 * @param program the current program, usually the target image. In general, this should be used
	 *            for at least two purposes. 1) To populate the default command line. 2) To ensure
	 *            the target image is mapped in the resulting target trace.
	 * @param script the batch file that implements this offer
	 * @return the offer
	 * @throws FileNotFoundException if the batch file does not exist
	 */
	public static BatchScriptTraceRmiLaunchOffer create(TraceRmiLauncherServicePlugin plugin,
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
		return new BatchScriptTraceRmiLaunchOffer(plugin, program, script,
			"BATCH_FILE:" + script.getName(), attrs);
	}

	private BatchScriptTraceRmiLaunchOffer(TraceRmiLauncherServicePlugin plugin, Program program,
			File script, String configName, ScriptAttributes attrs) {
		super(plugin, program, script, configName, attrs);
	}
}
