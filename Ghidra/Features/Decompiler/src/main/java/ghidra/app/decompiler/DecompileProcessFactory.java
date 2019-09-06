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
package ghidra.app.decompiler;

import java.io.File;
import java.io.FileNotFoundException;

import ghidra.framework.*;
import ghidra.util.Msg;

/**
 * Factory that returns a DecompileProcess.
 */
public class DecompileProcessFactory {

	private static String exepath;
	private static final String EXECNAME = "decompile";
	private static final String WIN32_EXECNAME = "decompile.exe";

	public synchronized static DecompileProcess get() {
		getExePath();
		DecompileProcess currentProcess = new DecompileProcess(exepath);
		return currentProcess;
	}

	public synchronized static void release(DecompileProcess dp) {
		dp.dispose();
	}

	private static void getExePath() {
		if (exepath != null) {
			return;
		}

		String exeName;
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
			exeName = WIN32_EXECNAME;
		}
		else {
			exeName = EXECNAME;
		}

		try {
			File file = Application.getOSFile(exeName);
			exepath = file.getAbsolutePath();
		}
		catch (FileNotFoundException e) {
			Msg.showError(DecompileProcessFactory.class, null, "Decompiler missing",
				"Could not find decompiler executable " + exeName);
		}
	}
}
