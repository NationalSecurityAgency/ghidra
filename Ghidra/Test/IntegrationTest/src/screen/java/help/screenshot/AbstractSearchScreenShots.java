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

import java.awt.Color;

import javax.swing.JFrame;

/*package*/ abstract class AbstractSearchScreenShots extends GhidraScreenShotGenerator {

	protected static final Color YELLOW_ORANGE = new Color(155, 150, 50);
	protected static final Color BLUE_GREEN = new Color(0, 128, 64);
	protected static final Color DARK_BLUE = new Color(0, 0, 128);
	protected static final Color DARK_GREEN = new Color(0, 128, 0);

	@Override
	protected String getHelpTopicName() {
		return "Search";
	}

	protected void moveTool(final int x, final int y) {
		runSwing(() -> {
			JFrame toolFrame = tool.getToolFrame();
			toolFrame.setLocation(x, y);
		});
	}
}
