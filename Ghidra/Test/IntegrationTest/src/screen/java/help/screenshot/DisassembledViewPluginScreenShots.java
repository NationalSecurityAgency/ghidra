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
package help.screenshot;

import java.awt.*;

import javax.swing.SwingUtilities;

import org.junit.Test;

import docking.ComponentProvider;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.programtree.ViewManagerComponentProvider;

public class DisassembledViewPluginScreenShots extends GhidraScreenShotGenerator {

	public DisassembledViewPluginScreenShots() {
		super();
	}

	@Test
	public void testDisassembledViewPluginMain() {
		setToolSize(900, 600);
		positionListingTop(0x4017ad);
		closeProvider(DataTypesProvider.class);
		closeProvider(ViewManagerComponentProvider.class);
		performAction("Disassembled View", "DockingWindows", true);
		captureWindow();

		ComponentProvider provider = getProvider("Virtual Disassembler - Current Instruction");
		Component component = getDockableComponent(provider);
		Rectangle r = component.getBounds();
		Point p = r.getLocation();
		p = SwingUtilities.convertPoint(component.getParent(), p, tool.getToolFrame());
		r.setLocation(p);

		// Highlight the component
		// Adjust the highlight.
		int offset = 2;
		Point location = r.getLocation();
		location.x += offset;// over
		location.y += offset;// down
		r.setLocation(location);

		Dimension size = r.getSize();
		size.width -= (2 * offset);// in
		size.height -= (2 * offset);// up
		r.setSize(size);

		drawRectangle(Color.YELLOW, r, 10);
	}

}
