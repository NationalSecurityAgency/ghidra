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
package ghidra.app.plugin.runtimeinfo;

import java.awt.BorderLayout;
import java.text.DecimalFormat;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.util.Disposable;
import ghidra.util.layout.PairLayout;

/**
 * A {@link JPanel} that displays live memory usage and provides a button to initiate garbage 
 * collection on-demand
 */
class MemoryUsagePanel extends JPanel implements Disposable {

	private static final DecimalFormat DECIMAL_FORMAT = new DecimalFormat();

	private Timer timer;

	/**
	 * Creates a new {@link MemoryUsagePanel}
	 */
	MemoryUsagePanel() {
		setLayout(new BorderLayout());

		// Center panel
		JPanel centerPanel = new JPanel(new PairLayout());
		centerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		JLabel maxMem = new GDLabel("00000000000", SwingConstants.RIGHT);
		JLabel totalMem = new GDLabel("00000000000", SwingConstants.RIGHT);
		JLabel freeMem = new GDLabel("00000000000", SwingConstants.RIGHT);
		JLabel usedMem = new GDLabel("00000000000", SwingConstants.RIGHT);
		centerPanel.add(new GLabel("Max Memory:"));
		centerPanel.add(maxMem);
		centerPanel.add(new GLabel("Total Memory:"));
		centerPanel.add(totalMem);
		centerPanel.add(new GLabel("Free Memory:"));
		centerPanel.add(freeMem);
		centerPanel.add(new GLabel("Used Memory:"));
		centerPanel.add(usedMem);
		add(centerPanel, BorderLayout.CENTER);

		// Bottom panel
		JPanel bottomPanel = new JPanel();
		JButton gcButton = new JButton("Collect Garbage");
		gcButton.addActionListener(e -> Runtime.getRuntime().gc());
		bottomPanel.add(gcButton);
		add(bottomPanel, BorderLayout.SOUTH);

		// Garbage collection refresh timer
		timer = new Timer(2000, e -> {
			Runtime runtime = Runtime.getRuntime();
			maxMem.setText(formatMemoryValue(runtime.maxMemory()));
			totalMem.setText(formatMemoryValue(runtime.totalMemory()));
			freeMem.setText(formatMemoryValue(runtime.freeMemory()));
			usedMem.setText(formatMemoryValue(runtime.totalMemory() - runtime.freeMemory()));
		});
	}

	@Override
	public void dispose() {
		timer.stop();
	}

	/**
	 * Should be called when this {@link MemoryUsagePanel} is shown
	 */
	void shown() {
		timer.start();
	}

	/**
	 * Should be called when this {@link MemoryUsagePanel} is hidden
	 */
	void hidden() {
		timer.stop();
	}

	/**
	 * Formats the given raw memory value (in bytes) to a more human-readable string
	 * 
	 * @param value A memory value in bytes
	 * @return A more human-readable memory value representation
	 */
	private String formatMemoryValue(long value) {
		return DECIMAL_FORMAT.format(value >>> 20) + "MB";
	}
}
