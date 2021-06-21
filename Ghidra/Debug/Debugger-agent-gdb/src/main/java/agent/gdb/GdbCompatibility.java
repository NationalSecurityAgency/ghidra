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
package agent.gdb;

import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.util.*;

import ghidra.dbg.util.ShellUtils;

public enum GdbCompatibility {
	INSTANCE;

	public static boolean checkGdbPresent(String path) {
		try {
			ProcessBuilder builder = new ProcessBuilder(path, "--version");
			builder.redirectError(Redirect.INHERIT);
			builder.redirectOutput(Redirect.INHERIT);
			@SuppressWarnings("unused")
			Process gdb = builder.start();
			// TODO: Once supported versions are decided, check the version.
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	private final Map<String, Boolean> cache = new HashMap<>();

	public boolean isCompatible(String gdbCmd) {
		List<String> args = ShellUtils.parseArgs(gdbCmd);
		if (args.isEmpty()) {
			return false;
		}
		return cache.computeIfAbsent(gdbCmd, p -> checkGdbPresent(args.get(0)));
	}
}
