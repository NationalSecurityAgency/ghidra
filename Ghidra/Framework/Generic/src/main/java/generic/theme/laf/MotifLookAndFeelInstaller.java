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
package generic.theme.laf;

import generic.theme.LafType;

public class MotifLookAndFeelInstaller extends LookAndFeelInstaller {

	public MotifLookAndFeelInstaller() {
		super(LafType.MOTIF);
	}

	@Override
	protected void fixupLookAndFeelIssues() {
		//
		// The Motif LaF does not bind copy/paste/cut to Control-C/V/X by default.  Rather, they
		// only use the COPY/PASTE/CUT keys.  The other LaFs bind both shortcuts.
		//

		// these prefixes are for text components
		String[] UIPrefixValues =
			{ "TextField", "FormattedTextField", "TextArea", "TextPane", "EditorPane" };

		setKeyBinding("COPY", "ctrl C", UIPrefixValues);
		setKeyBinding("PASTE", "ctrl V", UIPrefixValues);
		setKeyBinding("CUT", "ctrl X", UIPrefixValues);
	}
}
