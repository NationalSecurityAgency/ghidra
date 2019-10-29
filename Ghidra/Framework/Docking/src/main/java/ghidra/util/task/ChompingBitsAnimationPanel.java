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
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.util.AnimatedIcon;
import resources.ResourceManager;

/**
 * Panel that displays an animation of the Ghidra dragon chomping bits.
 */
public class ChompingBitsAnimationPanel extends JPanel {

	public ChompingBitsAnimationPanel() {
		setLayout(new BorderLayout());
		
		List<Icon> iconList = new ArrayList<>();
		iconList.add(ResourceManager.loadImage("images/eatbits1.png"));
		iconList.add(ResourceManager.loadImage("images/eatbits2.png"));
		iconList.add(ResourceManager.loadImage("images/eatbits3.png"));
		iconList.add(ResourceManager.loadImage("images/eatbits4.png"));
		iconList.add(ResourceManager.loadImage("images/eatbits5.png"));
		iconList.add(ResourceManager.loadImage("images/eatbits6.png"));
		iconList.add(ResourceManager.loadImage("images/eatbits7.png"));
		AnimatedIcon icon = new AnimatedIcon(iconList, 200, 0);
		setSize(new Dimension(200, 100));
		add(new JLabel(icon));
	}
}
