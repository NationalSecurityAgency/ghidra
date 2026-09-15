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
package ghidra.pcode.emu.symz3;

import ghidra.framework.*;

public class SymZ3 {
	public static void loadZ3Libs() {
		// Load the libraries using a custom search path before the system tries
		String ext = Platform.CURRENT_PLATFORM.getLibraryExtension();
		try {
			System.load(Application.getOSFile("libz3" + ext).getPath());
			System.load(Application.getOSFile("libz3java" + ext).getPath());
		}
		catch (OSFileNotFoundException e) {
			throw new UnsatisfiedLinkError("Z3 libs not found: " + e);
		}
		System.setProperty("z3.skipLibraryLoad", Boolean.toString(true));
	}
}
