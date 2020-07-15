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

import org.junit.Test;

import docking.action.DockingActionIf;
import ghidra.app.util.viewer.field.*;
import ghidra.graph.visualization.DefaultGraphDisplayComponentProvider;

public class ProgramGraphPluginScreenShots extends GhidraScreenShotGenerator {

	private static final int STARTX = 450;
	private static final int NUM_LINES = 31;
	private static final int WIDTH = 50;
	private int lineHeight;

	@Test
	public void testBasicBlockExampleCode() {
		env.showTool();
		removeField(BytesFieldFactory.FIELD_NAME);
		removeField(EolCommentFieldFactory.FIELD_NAME);
		removeField(XRefFieldFactory.FIELD_NAME);
		removeField(XRefHeaderFieldFactory.XREF_FIELD_NAME);
		removeFlowArrows();
		setToolSize(1000, 1200);
		captureListingRange(0x004010e0, 0x00401126, 650);
		int imageHeight = image.getHeight(null);
		lineHeight = imageHeight / NUM_LINES;
		drawBlockLines(0, 5, "Block 1");
		drawBlockLines(5, 7, "Block 2");
		drawBlockLines(7, 16, "Block 3");
		drawBlockLines(16, 18, "Block 4");
		drawBlockLines(18, 24, "Block 5");
		drawBlockLines(24, 28, "Block 6");
		drawBlockLines(28, 31, "Block 7");
		crop(new Rectangle(20, 0, 580, imageHeight));
	}

	@Test
	public void testBasicBlockGraph() {
		goToListing(0x004010e0);
		addSelection(0x004010e0, 0x00401126);
		DockingActionIf action = getAction(tool, "ProgramGraphPlugin", "Graph Block Flow");
		performAction(action);
		captureIsolatedProvider(DefaultGraphDisplayComponentProvider.class, 500, 950);
		int height = image.getHeight(null);
		int width = image.getWidth(null);
		crop(new Rectangle(50, 50, width - 100, height - 100));
	}

	@Test
	public void testCodeBlockGraph() {
		goToListing(0x00401a74);
		addSelection(0x00401a74, 0x00401a94);
		DockingActionIf action = getAction(tool, "ProgramGraphPlugin", "Graph Code Flow");
		performAction(action);

		captureIsolatedProvider(DefaultGraphDisplayComponentProvider.class, 1000, 1000);
		int height = image.getHeight(null);
		int width = image.getWidth(null);
		crop(new Rectangle(50, 250, width - 100, height - 500));
	}

	@Test
	public void testSelectGraphNode() {
		goToListing(0x40812d);
		addSelection(0x0040812d, 0x040813b);
		DockingActionIf action = getAction(tool, "ProgramGraphPlugin", "Graph Block Flow");
		performAction(action);
		makeSelection(0x00408133, 0x0408139);
		captureIsolatedProvider(DefaultGraphDisplayComponentProvider.class, 500, 750);
		int height = image.getHeight(null);
		int width = image.getWidth(null);
		crop(new Rectangle(50, 250, width - 200, height - 260));
	}

	@Test
	public void testFocusGraphNode() {
		goToListing(0x40812d);
		addSelection(0x0040812d, 0x040813b);
		DockingActionIf action = getAction(tool, "ProgramGraphPlugin", "Graph Block Flow");
		performAction(action);
		goToListing(0x408133);
		captureIsolatedProvider(DefaultGraphDisplayComponentProvider.class, 500, 750);
		int height = image.getHeight(null);
		int width = image.getWidth(null);
		crop(new Rectangle(50, 250, width - 200, height - 260));
	}

	private void drawBlockLines(int startLine, int endLine, String string) {
		int startY = startLine * lineHeight;
		int endY = endLine * lineHeight;
		Point p1 = new Point(STARTX, startY);
		Point p2 = new Point(STARTX + WIDTH, startY);
		Point p3 = new Point(STARTX, endY);
		Point p4 = new Point(STARTX + WIDTH, endY);
		drawLine(Color.BLACK, 3, p1, p2);
		drawLine(Color.BLACK, 3, p2, p4);
		drawLine(Color.BLACK, 3, p3, p4);
		drawText(string, Color.BLACK, new Point(STARTX + WIDTH + 10, (startY + endY) / 2), 12);
	}
}
