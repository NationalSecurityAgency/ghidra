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

import static org.junit.Assume.*;

import ghidra.framework.Platform;

/**
 * Utilities for SymZ3 testing
 */
public class SymZ3TestUtils {

	/**
	 * Checks to make sure the current {@link Platform} is supported by our default native binary
	 * set. If it's not supported, the test this is called from is skipped with an appropriate
	 * message.
	 */
	public static void skipTestIfUnsupportedPlatform() {
		boolean supportedPlatform = switch (Platform.CURRENT_PLATFORM) {
			case WIN_X86_64:
			case LINUX_X86_64:
			case MAC_ARM_64:
			case MAC_X86_64:
				yield true;
			default:
				yield false;
		};
		assumeTrue("Skipping test: Running on an unsupported platform", supportedPlatform);
	}
}
