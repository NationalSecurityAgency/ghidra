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

import java.awt.Font;
import java.util.Set;

import javax.swing.*;

import generic.theme.*;
import ghidra.util.exception.AssertException;

public class NimbusLookAndFeelManager extends LookAndFeelManager {

	public NimbusLookAndFeelManager() {
		super(LafType.NIMBUS);
	}

	@Override
	protected LookAndFeelInstaller getLookAndFeelInstaller() {
		return new NimbusLookAndFeelInstaller();
	}

	@Override
	public void resetAll(GThemeValueMap javaDefaults) {
		GColor.refreshAll();
		GIcon.refreshAll();
		reinstallNimubus();
	}

	public void updateFonts(String id, Set<String> affectedJavaIds, Font newFont) {
		if (!affectedJavaIds.isEmpty()) {
			reinstallNimubus();
		}
		repaintAll();
	}

	public void updateIcons(String id, Set<String> affectedJavaIds, Icon newIcon) {
		if (!affectedJavaIds.isEmpty()) {
			reinstallNimubus();
		}
		GIcon.refreshAll();
		repaintAll();
	}

	private void reinstallNimubus() {
		try {
			UIManager.setLookAndFeel(new GNimbusLookAndFeel() {
				protected GThemeValueMap extractJavaDefaults(UIDefaults defaults) {
					return Gui.getJavaDefaults();
				}
			});
		}
		catch (UnsupportedLookAndFeelException e) {
			throw new AssertException("This can't happen, we are just re-installing the same L&F");
		}
		updateComponentUis();
	}

}
