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
package ghidra.graph.visualization;

import java.awt.BorderLayout;

import javax.swing.*;

import org.jungrapht.visualization.layout.algorithms.LayoutAlgorithm;

import docking.DialogComponentProvider;
import ghidra.service.graph.AttributedVertex;

/**
 * Extends DialogComponentProvider to make a dialog with buttons to show that the
 * layout arrangement algorithm is busy
 */
public class LayoutWorkingDialog extends DialogComponentProvider {

	public LayoutWorkingDialog(LayoutAlgorithm<AttributedVertex> layoutAlgorithm) {
		super("Working....", false);
		super.addWorkPanel(createPanel(layoutAlgorithm));
		setRememberSize(false);
		addDismissButton();
		setDefaultButton(dismissButton);
	}

	/**
	 * Create a layout-formatted JComponent holding 2 vertical lists
	 * of buttons, one list for vertex filter buttons and one list for
	 * edge filter buttons. Each list has a border and title.
	 * @return a formatted JComponent (container)
	 */
	JComponent createPanel(LayoutAlgorithm<AttributedVertex> layoutAlgorithm) {
		JProgressBar progressBar = new JProgressBar();
		progressBar.setIndeterminate(true);
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(progressBar, BorderLayout.CENTER);
		panel.add(new JLabel("Please wait......."), BorderLayout.NORTH);
		addCancelButton();
		cancelButton.addActionListener(evt -> layoutAlgorithm.cancel());
		return panel;
	}
}
