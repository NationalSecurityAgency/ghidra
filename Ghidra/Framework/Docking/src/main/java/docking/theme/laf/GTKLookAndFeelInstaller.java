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
package docking.theme.laf;

import javax.swing.*;

import docking.theme.LafType;

public class GTKLookAndFeelInstaller extends LookAndFeelInstaller {

	public GTKLookAndFeelInstaller() {
		super(LafType.GTK);
	}

	@Override
	protected void installLookAndFeel() throws ClassNotFoundException, InstantiationException,
			IllegalAccessException, UnsupportedLookAndFeelException {

		super.installLookAndFeel();
		LookAndFeel lookAndFeel = UIManager.getLookAndFeel();
		WrappingLookAndFeel wrappingLookAndFeel = new WrappingLookAndFeel(lookAndFeel);
		UIManager.setLookAndFeel(wrappingLookAndFeel);
	}

	@Override
	protected void installJavaDefaults() {
		// handled by WrappingLookAndFeel
	}

}
