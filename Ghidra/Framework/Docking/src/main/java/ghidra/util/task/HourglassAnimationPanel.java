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
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.util.AnimatedIcon;
import resources.ResourceManager;

/**
 * Panel that displays an animation of a spinning hourglass
 */
public class HourglassAnimationPanel extends JPanel {

	public HourglassAnimationPanel() {
		
		setLayout(new BorderLayout());
		
		List<Icon> iconList = new ArrayList<>();
		iconList.add(ResourceManager.loadImage("images/hourglass24_01.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_02.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_02.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_03.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_03.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_04.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_04.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_05.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_05.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_06.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_06.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_07.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_07.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_08.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_08.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_09.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_10.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_11.png"));
		AnimatedIcon progressIcon = new AnimatedIcon(iconList, 150, 0);
		
		add(new JLabel(progressIcon), BorderLayout.NORTH);
	}
}
