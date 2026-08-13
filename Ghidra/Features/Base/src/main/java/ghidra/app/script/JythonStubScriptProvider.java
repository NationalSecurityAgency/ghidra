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
package ghidra.app.script;

import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * A stub {@link GhidraScriptProvider} used to give feedback to a user trying to run a Jython
 * script when the Jython Extension is not installed.
 * <p>
 * Uses a sub-{@link ExtensionPointProperties#DEFAULT_PRIORITY default} priority so the Jython 
 * Extension can get prioritized over this if it's installed.
 */
@ExtensionPointProperties(priority = ExtensionPointProperties.DEFAULT_PRIORITY - 1)
public class JythonStubScriptProvider extends AbstractPythonScriptProvider {

	@Override
	public String getDescription() {
		return "Jython";
	}

	@Override
	public String getRuntimeEnvironmentName() {
		return "Jython";
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws JythonStubException {
		throw new JythonStubException();
	}

	/**
	 * A special type of {@link GhidraScriptLoadException} used to indicate that the Jython
	 * Extension is not installed.
	 */
	public static class JythonStubException extends GhidraScriptLoadException {

		/**
		 * Construct an new {@link JythonStubException}
		 */
		public JythonStubException() {
			super("Jython script failed. " +
				"In order to use Jython based scripts, you must install the Jython Ghidra " +
				"Extension, or (recommended) port your script to PyGhidra or Java.");
		}
	}
}
