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
package ghidra.app.plugin.debug;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.DecimalFormat;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingUtils;
import ghidra.util.layout.PairLayout;

class ShowMemoryDialog extends DialogComponentProvider {
	private MemoryUsagePlugin plugin;
	private JLabel maxMem;
	private JLabel totalMem;
	private JLabel freeMem;
	private JLabel usedMem;
	private Timer timer;

	ShowMemoryDialog(MemoryUsagePlugin plugin) {
		super("VM Memory Usage", false, false, true, false);
		this.plugin = plugin;
		addOKButton();
		setOkButtonText("GC");
		addWorkPanel(createWorkPanel());
		plugin.getTool().showDialog(this);
		final DecimalFormat df = new DecimalFormat();
		timer = new Timer(2000, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				Runtime runtime = Runtime.getRuntime();
				maxMem.setText(df.format(runtime.maxMemory() / 1000) + "K");
				totalMem.setText(df.format(runtime.totalMemory() / 1000) + "K");
				freeMem.setText(df.format(runtime.freeMemory() / 1000) + "K");
				usedMem.setText(
					df.format((runtime.totalMemory() - runtime.freeMemory()) / 1000) + "K");
			}
		});
		timer.start();
	}

	boolean isInitialized() {
		String text = maxMem.getText();
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if ('0' != c) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected void cancelCallback() {
		timer.stop();
		plugin.clearDialog();
		super.cancelCallback();
	}

	@Override
	protected void okCallback() {
		Runtime.getRuntime().gc();
	}

	private JComponent createWorkPanel() {
		JPanel panel = new JPanel(new PairLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		maxMem = DockingUtils.createNonHtmlLabel("00000000000", SwingConstants.RIGHT);
		totalMem = DockingUtils.createNonHtmlLabel("00000000000", SwingConstants.RIGHT);
		freeMem = DockingUtils.createNonHtmlLabel("00000000000", SwingConstants.RIGHT);
		usedMem = DockingUtils.createNonHtmlLabel("00000000000", SwingConstants.RIGHT);

		panel.add(DockingUtils.createNonHtmlLabel("Max Memory:"));
		panel.add(maxMem);
		panel.add(DockingUtils.createNonHtmlLabel("Total Memory:"));
		panel.add(totalMem);
		panel.add(DockingUtils.createNonHtmlLabel("Free Memory:"));
		panel.add(freeMem);
		panel.add(DockingUtils.createNonHtmlLabel("Used Memory:"));
		panel.add(usedMem);

		return panel;
	}
}
