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
package ghidra.app.plugin.core.instructionsearch.ui;

import java.awt.Component;
import java.awt.FlowLayout;

import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.border.*;

/**
 * Abstract class to be used as the base for any widgets that need to be shown in the
 * {@link ControlPanel}.
 *
 */
public abstract class ControlPanelWidget extends JPanel {

	/**
	 * 
	 */
	public ControlPanelWidget( String title) {

		this.setLayout(new FlowLayout());
		setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
		setAlignmentX(Component.LEFT_ALIGNMENT);

		TitledBorder componentBorder = new TitledBorder(title);
		Border margin = new EmptyBorder(5, 5, 5, 5);
		setBorder(new CompoundBorder(componentBorder, margin));

		this.add(createContent());
	}

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/

	/**
	 * Override to create the container for the widgets you want to display.
	 * 
	 * @return
	 */
	protected abstract JPanel createContent();
}
