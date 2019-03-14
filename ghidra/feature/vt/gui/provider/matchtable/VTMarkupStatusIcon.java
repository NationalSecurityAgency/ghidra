/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.provider.matchtable;

import ghidra.feature.vt.api.main.VTAssociationMarkupStatus;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

public class VTMarkupStatusIcon implements Icon {
	private int BORDER = 2;
	private int WIDTH = 44;
	private int KNOB_WIDTH = 4;
	private int HEIGHT = 16;
	private VTAssociationMarkupStatus status = new VTAssociationMarkupStatus(0xff);

	@Override
	public int getIconHeight() {
		return HEIGHT;
	}

	@Override
	public int getIconWidth() {
		return WIDTH + KNOB_WIDTH;
	}

	void setStatus(VTAssociationMarkupStatus status) {
		this.status = status;

	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		List<Color> colors = getColors(status);
		int numColors = colors.size();

		double size = numColors == 0 ? 0 : ((double) WIDTH - 2 * BORDER - 1) / numColors;
		if (status.hasUnexaminedMarkup()) {
			size /= 2;
		}

		for (int i = 0; i < numColors; i++) {
			int startX = (int) (i * size);
			int endX = (int) ((i + 1) * size);
			int width = endX - startX;
			drawBar(g, x + startX + BORDER + 1, y + BORDER + 1, width, colors.get(i));
		}

		g.setColor(Color.BLACK);
		g.drawRect(x, y, WIDTH, HEIGHT);
//		g.drawRect(x, y, WIDTH / 2, HEIGHT);
		g.drawRect(x + WIDTH, y + HEIGHT / 2 - 3, KNOB_WIDTH, 6);

	}

	private void drawBar(Graphics g, int x, int y, int width, Color color) {
		g.setColor(color);
		g.fillRect(x, y, width, HEIGHT - 2 * BORDER - 1);
	}

	private List<Color> getColors(VTAssociationMarkupStatus status) {
		Color ORANGE = new Color(255, 150, 0);
		Color GREEN = new Color(0, 180, 0);
		Color BLUE = new Color(80, 80, 240);
		List<Color> list = new ArrayList<Color>(4);
		if (status.hasRejectedMarkup()) {
			list.add(Color.RED);
		}
		if (status.hasAppliedMarkup() || status.isFullyApplied()) {
			list.add(GREEN);
		}
		if (status.hasDontCareMarkup()) {
			list.add(BLUE);
		}
		if (status.hasDontKnowMarkup()) {
			list.add(ORANGE);
		}
		return list;
	}

}
