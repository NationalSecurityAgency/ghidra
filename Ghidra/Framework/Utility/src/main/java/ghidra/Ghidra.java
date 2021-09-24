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
package ghidra;

import java.awt.Taskbar;

/**
 * Ghidra entry point that forwards the command line arguments to {@link GhidraLaunchable}.
 * <p>
 * This class was introduced so Ghidra's application name can be set to "ghidra-Ghidra" on Linux,
 * rather than "ghidra-GhidraLauncher".
 * @see <a href="https://bugs.java.com/bugdatabase/view_bug.do?bug_id=6528430">JDK-6528430</a>
 */
public class Ghidra {

	/**
	 * Launches the given {@link GhidraLaunchable} specified in the first command line argument
	 * 
	 * @param args The first argument is the name of the {@link GhidraLaunchable} to launch.
	 *   The remaining args get passed through to the class's {@link GhidraLaunchable#launch} 
	 *   method.
	 * @throws Exception If there was a problem launching.  See the exception's message for more
	 *     details on what went wrong.  
	 */
	public static void main(String[] args) throws Exception {
		
		// Poke the Taskbar class in order to set the Linux application name to this class's
		// fully qualified class name (with . replaced by -). If we don't do this here, the next 
		// time it gets done is in a new thread, which results in the application name being set to 
		// "java-lang-thread".
		Taskbar.isTaskbarSupported();
		
		// Forward args to GhidraLauncher, which will perform the launch
		GhidraLauncher.launch(args);
	}
}
