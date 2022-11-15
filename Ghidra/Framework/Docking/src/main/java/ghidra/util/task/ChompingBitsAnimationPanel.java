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
package ghidra.util.task;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.List;

import javax.swing.*;

import docking.util.AnimatedIcon;
import generic.theme.GIcon;

/**
 * Panel that displays an animation of the Ghidra dragon eating bits.
 */
public class ChompingBitsAnimationPanel extends JPanel {

	//@formatter:off
	private static final List<Icon> ICONS = List.of(
		new GIcon("icon.task.progress.1"),
		new GIcon("icon.task.progress.2"),
		new GIcon("icon.task.progress.3"),
		new GIcon("icon.task.progress.4"),
		new GIcon("icon.task.progress.5"),
		new GIcon("icon.task.progress.6"),
		new GIcon("icon.task.progress.7")
		);
	//@formatter:on

	public ChompingBitsAnimationPanel() {
		setLayout(new BorderLayout());

		AnimatedIcon icon = new AnimatedIcon(ICONS, 200, 0);
		setSize(new Dimension(200, 100));
		add(new JLabel(icon));
	}
}
