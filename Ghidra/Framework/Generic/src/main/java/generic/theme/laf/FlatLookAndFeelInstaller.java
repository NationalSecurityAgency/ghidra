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

import javax.swing.UIManager;

import generic.theme.LafType;

public class FlatLookAndFeelInstaller extends LookAndFeelInstaller {

	public FlatLookAndFeelInstaller(LafType lookAndFeelType) {
		super(lookAndFeelType);
	}

	@Override
	protected void fixupLookAndFeelIssues() {
		super.fixupLookAndFeelIssues();

		// We have historically managed button focusability ourselves.  Allow this by default so
		// features continue to work as expected, such as right-clicking on ToolButtons.
		UIManager.put("ToolBar.focusableButtons", Boolean.TRUE);
	}

}
