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
package sarif.view;

import java.awt.image.BufferedImage;

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.ComponentProvider;
import docking.widgets.imagepanel.ImagePanel;
import ghidra.framework.plugintool.PluginTool;

/**
 * For displaying Image artifacts from a SARIF file
 *
 */
public class ImageArtifactDisplay extends ComponentProvider {
	public ImagePanel label;

	public ImageArtifactDisplay(PluginTool tool, String name, String owner, BufferedImage img) {
		super(tool, name, owner);
		label = new ImagePanel(new ImageIcon(img).getImage());
	}

	@Override
	public JComponent getComponent() {
		return label;
	}

	public void dispose() {
		closeComponent();
	}
}
