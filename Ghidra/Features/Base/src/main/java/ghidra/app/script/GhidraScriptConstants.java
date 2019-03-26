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

/**
 * A class to hold constants to be shared for clients of this package.
 * 
 * <P>This class should not depend on any classes in this package in order to prevent static
 * loading of data.
 */
public class GhidraScriptConstants {

	/**
	 * The system property that overrides the location of the source directory used to store
	 * Ghidra scripts
	 */
	public static final String USER_SCRIPTS_DIR_PROPERTY = "ghidra.user.scripts.dir";

	/**
	 * Default name of new scripts
	 */
	public static final String DEFAULT_SCRIPT_NAME = "NewScript";

	private GhidraScriptConstants() {
		// utility class
	}
}
