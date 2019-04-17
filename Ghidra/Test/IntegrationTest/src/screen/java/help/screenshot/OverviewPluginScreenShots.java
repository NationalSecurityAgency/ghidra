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

import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.overview.OverviewColorLegendDialog;
import ghidra.app.plugin.core.overview.OverviewColorPlugin;
import ghidra.app.plugin.core.overview.addresstype.AddressTypeOverviewColorService;
import ghidra.app.plugin.core.overview.addresstype.AddressTypeOverviewLegendPanel;
import ghidra.app.plugin.core.overview.entropy.*;

public class OverviewPluginScreenShots extends GhidraScreenShotGenerator {

	private AddressTypeOverviewColorService addressTypeService;
	private EntropyOverviewColorService entropyService;

	public OverviewPluginScreenShots() {
		super();
	}

	@Override
	public void setUp() throws Exception {
		super.setUp();
		addressTypeService = new AddressTypeOverviewColorService();
		entropyService = new EntropyOverviewColorService();
		addressTypeService.initialize(tool);
		entropyService.initialize(tool);
	}

	@Test
	public void testOverviewPanel() {
		showProvider(CodeViewerProvider.class);
		OverviewColorPlugin plugin = getPlugin(tool, OverviewColorPlugin.class);

		runSwing(() -> {
			plugin.installOverview(addressTypeService);
		});

		captureIsolatedProvider(CodeViewerProvider.class, 700, 400);
		padImage(new Color(0, 0, 0, 0), 10, 0, 50, 0);
		drawOval(Color.RED, new Rectangle(630, 2, 40, 40), 3);
		drawOval(Color.RED, new Rectangle(668, 55, 40, 240), 3);
	}

	@Test
	public void testAddressTypeOverviewLegend() {
		AddressTypeOverviewLegendPanel legendPanel =
			new AddressTypeOverviewLegendPanel(addressTypeService);
		OverviewColorLegendDialog legendDialog =
			new OverviewColorLegendDialog("Overview Legend", legendPanel, null);

		tool.showDialog(legendDialog);
		captureDialog();
	}

	@Test
	public void testEntropyLegend() {
		EntropyOverviewOptionsManager options =
			new EntropyOverviewOptionsManager(tool, entropyService);
		Palette palette = options.getPalette();
		LegendPanel legendPanel = new LegendPanel();
		legendPanel.setPalette(palette);
		OverviewColorLegendDialog legendDialog =
			new OverviewColorLegendDialog("Entropy Legend", legendPanel, null);

		tool.showDialog(legendDialog);
		captureDialog();
	}

	@Test
	public void testEntropyOptions() {
		showOptions("Entropy");
		captureDialog(900, 510);
	}

	@Test
	public void testEquation() {
		int margin = 20;
		image = createEmptyImage(10, 10);
		Graphics g = image.getGraphics();

		Font font = new Font("Times New Roman", Font.PLAIN, 30);
		FontMetrics metrics = g.getFontMetrics(font);

		Font bigFont = font.deriveFont(55f);
		FontMetrics bigMetrics = g.getFontMetrics(bigFont);

		Font mediumFont = new Font("STIXGeneral", Font.PLAIN, 30);

		Font smallFont = new Font("STIXGeneral", Font.PLAIN, 16);
		FontMetrics smallMetrics = g.getFontMetrics(font);

		char[] pChars = Character.toChars(0x1d45d);
		char[] iChars = Character.toChars(0x1d456);
		String mathyP = "" + pChars[0] + pChars[1];
		String mathyI = "" + iChars[0] + iChars[1];

		String sum = "\u2211";
		String sumTop = " 255";
		String sumBottom = " " + mathyI + "=0";
		String equation = " -" + mathyP + "(" + iChars[0] + iChars[1] + ") \u22c5 log\u2082(" +
			mathyP + "(" + mathyI + "))";

		int width = bigMetrics.stringWidth(sum) + metrics.stringWidth(equation);
		int bigFontHeight = bigMetrics.getAscent();
		int smallFontHeight = smallMetrics.getAscent();
		int height = bigFontHeight + 2 * smallFontHeight;

		image = createEmptyImage(width + margin * 2, height + margin * 2);

		Point p = new Point(margin, margin + smallFontHeight);
		drawText(sumTop, Color.BLACK, p, smallFont);

		p.y += bigMetrics.getAscent() - bigMetrics.getDescent() / 2;
		drawText(sum, Color.BLACK, p, bigFont);

		p.y += smallFontHeight;
		drawText(sumBottom, Color.BLACK, p, smallFont);

		p.x += bigMetrics.stringWidth(sum);
		p.y = margin + smallFontHeight + bigFontHeight / 2 + metrics.getHeight() / 2 -
			bigMetrics.getDescent() / 2;
		drawText(equation, Color.BLACK, p, mediumFont);

	}

}
