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
import java.util.List;

import javax.swing.*;

import docking.util.AnimatedIcon;
import generic.theme.GIcon;

/**
 * Panel that displays an animation of a spinning hourglass
 */
public class HourglassAnimationPanel extends JPanel {

	//@formatter:off
	private static final List<Icon> ICONS = List.of(
		new GIcon("icon.task.progress.hourglass.1"),
		new GIcon("icon.task.progress.hourglass.2"),
		new GIcon("icon.task.progress.hourglass.2"),
		new GIcon("icon.task.progress.hourglass.3"),
		new GIcon("icon.task.progress.hourglass.3"),
		new GIcon("icon.task.progress.hourglass.4"),
		new GIcon("icon.task.progress.hourglass.4"),
		new GIcon("icon.task.progress.hourglass.5"),
		new GIcon("icon.task.progress.hourglass.5"),
		new GIcon("icon.task.progress.hourglass.6"),
		new GIcon("icon.task.progress.hourglass.6"),
		new GIcon("icon.task.progress.hourglass.7"),
		new GIcon("icon.task.progress.hourglass.7"),
		new GIcon("icon.task.progress.hourglass.8"),
		new GIcon("icon.task.progress.hourglass.8"),
		new GIcon("icon.task.progress.hourglass.9"),
		new GIcon("icon.task.progress.hourglass.10"),
		new GIcon("icon.task.progress.hourglass.11")
	);
	//@formatter:on

	public HourglassAnimationPanel() {
		setLayout(new BorderLayout());
		AnimatedIcon progressIcon = new AnimatedIcon(ICONS, 150, 0);
		add(new JLabel(progressIcon), BorderLayout.NORTH);
	}
}
