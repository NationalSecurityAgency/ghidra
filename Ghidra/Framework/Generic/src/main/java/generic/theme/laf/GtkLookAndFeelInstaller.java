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

import javax.swing.LookAndFeel;
import javax.swing.UnsupportedLookAndFeelException;

import generic.theme.LafType;

/**
 * LookAndFeelInstaller for the GTK {@link LookAndFeel}
 */
public class GtkLookAndFeelInstaller extends LookAndFeelInstaller {

	public GtkLookAndFeelInstaller() {
		super(LafType.GTK);
	}

	@Override
	protected void installLookAndFeel() throws ClassNotFoundException, InstantiationException,
			IllegalAccessException, UnsupportedLookAndFeelException {

		super.installLookAndFeel();
	}

//	@Override
//	protected void installJavaDefaults() {
//		// GTK does not support changing its values, so set the javaDefaults to an empty map
//		Gui.setJavaDefaults(new GThemeValueMap());
//	}
//
}
