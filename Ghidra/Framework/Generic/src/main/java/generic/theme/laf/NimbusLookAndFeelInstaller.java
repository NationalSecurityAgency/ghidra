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

import java.awt.Dimension;

import javax.swing.*;

import generic.theme.*;

public class NimbusLookAndFeelInstaller extends LookAndFeelInstaller {

	public NimbusLookAndFeelInstaller() {
		super(LafType.NIMBUS);
	}

	@Override
	protected void installLookAndFeel() throws UnsupportedLookAndFeelException {
		UIManager.setLookAndFeel(new GNimbusLookAndFeel());
	}

	@Override
	protected void installJavaDefaults() {
		// even though java defaults have been installed, we need to fix them up now
		// that Nimbus has finished initializing
		GColor.refreshAll();
		Gui.setJavaDefaults(Gui.getJavaDefaults());
	}

	@Override
	protected void fixupLookAndFeelIssues() {
		super.fixupLookAndFeelIssues();

		// fix scroll bar grabber disappearing.  See https://bugs.openjdk.java.net/browse/JDK-8134828
		// This fix looks like it should not cause harm even if the bug is fixed on the jdk side.
		UIDefaults defaults = UIManager.getDefaults();
		defaults.put("ScrollBar.minimumThumbSize", new Dimension(30, 30));

		// (see NimbusDefaults for key values that can be changed here)
	}
}
