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
package docking.dnd;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;

/**
 * Provides a place for clients to retrieve the Clipboard they should be using.  This class
 * provides a level of indirection that allows us to inject clipboards as needed.
 * 
 * <P>Note: if a test needs to check the contents of the native clipboard, such as after 
 * executing a native Java action that uses the system clipboard, then that test must use some 
 * other mechanism to know that the native action was executed.   This is due to the fact that 
 * the system clipboard is potentially used by multiple Java test processes at once.
 */
public class GClipboard {

	private static Clipboard systemClipboard;

	/**
	 * Returns the clipboard that should be used by the current JVM
	 * @return the clipboard
	 */
	public static Clipboard getSystemClipboard() {
		if (systemClipboard == null) {
			systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		}
		return systemClipboard;
	}

	private GClipboard() {
		// utility class
	}

}
