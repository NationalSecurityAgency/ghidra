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
package help;

import utilities.util.reflection.ReflectionUtilities;

/**
 * Contains helpful methods for emitting messages to the console.
 */
public class GHelpMsg {

	public static void error(String message) {
		error(message, null);
	}

	public static void error(String message, Throwable t) {

		flush();

		try {
			// give the output thread a chance to finish it's output (this is a workaround for
			// the Eclipse editor, and its use of two threads in its console).
			Thread.sleep(250);
		}
		catch (InterruptedException e) {
			// don't care; we tried
		}

		String caller = ReflectionUtilities.getClassNameOlderThan(GHelpMsg.class);
		int index = caller.lastIndexOf('.');
		caller = caller.substring(index + 1);

		System.err.println("[" + caller + "] " + message);
		if (t != null) {
			t.printStackTrace();
		}

		flush();
	}

	public static void flush() {
		System.out.flush();
		System.out.println();
		System.out.flush();
		System.err.flush();
		System.err.println();
		System.err.flush();
	}
}
