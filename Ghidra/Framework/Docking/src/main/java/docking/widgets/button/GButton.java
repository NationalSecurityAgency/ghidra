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
package docking.widgets.button;

import javax.swing.Icon;
import javax.swing.JButton;

import resources.ResourceManager;

/**
 * A drop-in replacement for {@link JButton} that correctly installs a disable icon.
 */
public class GButton extends JButton {

	public GButton() {
		super();
	}

	public GButton(Icon icon) {
		super(icon);
	}

	public GButton(String text) {
		super(text);
	}

	@Override
	public void setIcon(Icon newIcon) {
		Icon disabledIcon = ResourceManager.getDisabledIcon(newIcon);
		setDisabledIcon(disabledIcon);
		super.setIcon(newIcon);
	}
}
