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

import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import com.formdev.flatlaf.FlatLaf;

public class FlatLookAndFeelInstaller extends LookAndFeelInstaller {
	private FlatLaf lookAndFeel;

	public FlatLookAndFeelInstaller(FlatLaf lookAndFeel) {
		this.lookAndFeel = lookAndFeel;
	}

	@Override
	protected void installLookAndFeel() throws UnsupportedLookAndFeelException {
		UIManager.setLookAndFeel(lookAndFeel);
	}

	@Override
	public boolean isSupportedForCurrentPlatform() {
		return true;
	}

}
