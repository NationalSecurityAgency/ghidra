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

import static org.junit.Assert.assertNotNull;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;

import javax.swing.*;

import org.junit.Test;

import ghidra.app.merge.MergeProgressPanel;
import ghidra.util.layout.VerticalLayout;
import resources.ResourceManager;

public class RepositoryCustomScreenShots extends GhidraScreenShotGenerator {

	public RepositoryCustomScreenShots() {
		super();
	}

	@Test
	public void testMultiUser() {
		image = createEmptyImage(800, 600);
		Color purple = new Color(255, 0, 255);
		Color green = new Color(100, 255, 100);
		int y = 50;
		int x = 450;
		int spacing = 100;
		int hSpacing = 170;
		Point p_v0 = new Point(x, y);
		Point p_v1 = new Point(x, y + spacing);
		Point p_v2 = new Point(x, y + 3 * spacing);
		Point p_v3 = new Point(x, y + 5 * spacing);
		Point p_co_v1 = new Point(x - hSpacing, y + (2 * spacing));
		Point p_co_v2 = new Point(x + hSpacing, y + (2 * spacing));
		Point p_box1 = new Point(x - hSpacing * 2, y + 3 * spacing);
		Point p_box2 = new Point(x - (hSpacing * 3) / 2, y + 4 * spacing);
		Point p_text1 = new Point(x + hSpacing / 2, y);
		Point p_text2 = new Point(x + hSpacing / 2, y + spacing / 2);
		Point p_text3 = new Point(x - 5 * hSpacing / 4, y + 5 * spacing / 4);
		Point p_text4 = new Point(x + 3 * hSpacing / 4, y + 5 * spacing / 4);
		Point p_text5 = new Point(x + hSpacing / 2, y + 11 * spacing / 4);
		Point p_text8 = new Point(x - 3 * hSpacing / 2, y + 5 * spacing);
		Point p_legend = new Point(x + hSpacing / 2, y + 4 * spacing);
		int indent = 50;
		int legendSpacing = 20;
		Point p_leg1 = new Point(x + hSpacing / 2, y + 4 * spacing + 2 * legendSpacing);
		Point p_leg2 = new Point(x + hSpacing / 2, y + 4 * spacing + 3 * legendSpacing);
		Point p_leg3 = new Point(x + hSpacing / 2, y + 4 * spacing + 4 * legendSpacing);
		Point p_leg1_text = new Point(p_leg1.x + indent, p_leg1.y);
		Point p_leg2_text = new Point(p_leg2.x + indent, p_leg2.y);
		Point p_leg3_text = new Point(p_leg3.x + indent, p_leg3.y);

		drawLine(purple, p_v0, p_v3, false);
		drawLine(Color.BLACK, p_v1, p_co_v1, true);
		drawLine(Color.BLACK, p_v1, p_co_v2, true);
		drawLine(green, p_co_v1, p_box1, false);
		drawLine(green, p_box1, p_box2, false);
		drawLine(Color.BLUE, p_co_v2, p_v2, false);
		drawLine(Color.BLUE, p_box2, p_v3, false);

		drawBubble("Version 0", null, p_v0);
		drawBubble("Version 1", null, p_v1);
		drawBubble("Version 2", null, p_v2);
		drawBubble("Version 3", null, p_v3);
		drawBubble("Check out", "Version 1", p_co_v1);
		drawBubble("Check out", "Version 1", p_co_v2);
		drawBox(p_box1, 6, "User A checks", "in his file");
		drawBox(p_box2, 7, "Ghidra Server merges file", "with the latest version which is",
			"Version 2, and creates", "Version 3");
		drawText(p_text1, 1, "File is added to Version Control", "Version 0 is created.");
		drawText(p_text2, 2, "A user checks out Version 0", "checks it in and creates Version 1.");
		drawText(p_text3, 3, "User A checks out", "Version 1.");
		drawText(p_text4, 4, "User B checks out", "Version 1.");
		drawText(p_text5, 5, "User B checks in his file", "and creates Version 2.");
		drawText(p_text8, 8, "User A must resolve any conflicts", "that may occur in order to",
			"complete the check in process.");

		drawText(p_legend, -1, "Note: The different colored lines denote",
			"phases of the check in process.");
		drawText(p_leg1_text, -1, "  Check Out");
		drawText(p_leg2_text, -1, "  Make changes and merge");
		drawText(p_leg3_text, -1, "  Create new version");
		drawLine(Color.BLACK, p_leg1, p_leg1_text, true);
		drawLine(green, p_leg2, p_leg2_text, false);
		drawLine(Color.BLUE, p_leg3, p_leg3_text, false);
	}

	private void drawLine(Color color, Point p1, Point p2, boolean dashed) {
		Graphics2D g = ((BufferedImage) image).createGraphics();
		BasicStroke dash = new BasicStroke(2f, BasicStroke.CAP_SQUARE, BasicStroke.JOIN_MITER, 1f,
			new float[] { 10f }, 0f);
		BasicStroke stroke = dashed ? dash : new BasicStroke(2f);
		g.setStroke(stroke);
		g.setColor(color);
		g.drawLine(p1.x, p1.y, p2.x, p2.y);
		g.dispose();
	}

	private void drawBubble(String text1, String text2, Point p) {
		int radius = 30;
		Graphics2D g = ((BufferedImage) image).createGraphics();
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		BasicStroke stroke = new BasicStroke(1);
		g.setStroke(stroke);

		int x = p.x - radius;
		int y = p.y - radius;
		g.fillOval(x, y, radius * 2, 2 * radius);

		Font f = g.getFont().deriveFont(12f);
		g.setFont(f);
		FontMetrics metrics = g.getFontMetrics();
		int height = metrics.getHeight();
		g.setColor(Color.BLACK);
		g.drawOval(x, y, radius * 2, radius * 2);

		if (text2 == null) {
			g.drawString(text1, p.x - metrics.stringWidth(text1) / 2,
				p.y + metrics.getAscent() / 2);
		}
		else {
			g.drawString(text1, p.x - metrics.stringWidth(text1) / 2,
				p.y - height / 2 + metrics.getAscent() / 2);
			g.drawString(text2, p.x - metrics.stringWidth(text2) / 2,
				p.y + height / 2 + metrics.getAscent() / 2);
		}
		g.dispose();
	}

	private void drawBox(Point p, int order, String... text) {
		Graphics2D g = ((BufferedImage) image).createGraphics();
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		BasicStroke stroke = new BasicStroke(1);
		g.setStroke(stroke);

		Font f = g.getFont().deriveFont(12f);
		g.setFont(f);
		FontMetrics metrics = g.getFontMetrics();
		int margin = 5;
		int height = metrics.getHeight() * text.length + 2 * margin;
		int width = 0;
		for (String string : text) {
			width = Math.max(width, metrics.stringWidth(string));
		}
		width += 2 * margin;

		int x = p.x - width / 2;
		int y = p.y - height / 2;
		g.fillRect(x, y, width, height);

		g.setColor(Color.BLACK);
		g.drawRect(x, y, width, height);

		y += margin;
		for (String string : text) {
			g.drawString(string, p.x - metrics.stringWidth(string) / 2, y + metrics.getAscent());
			y += metrics.getHeight();
		}

		String orderString = "(" + order + ")  ";
		g.drawString(orderString, x - metrics.stringWidth(orderString),
			p.y + metrics.getAscent() / 2);

		g.dispose();
	}

	private void drawText(Point p, int order, String... text) {
		Graphics2D g = ((BufferedImage) image).createGraphics();
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		Font f = g.getFont().deriveFont(12f);
		g.setFont(f);
		FontMetrics metrics = g.getFontMetrics();
//		int margin = 5;
		int height = metrics.getHeight() * text.length;
//		int width = 0;
//		for (String string : text) {
//			width = Math.max(width, metrics.stringWidth(string));
//		}
//		width += 2 * margin;
//
//		int x = p.x - width / 2;
//		int y = p.y - height / 2;
//		g.fillRect(x, y, width, height);

		g.setColor(Color.BLACK);
		int y = p.y - height / 2;
		int x = p.x;

		for (String string : text) {
			g.drawString(string, x, y + metrics.getAscent());
			y += metrics.getHeight();
		}
		if (order > 0) {
			String orderString = "(" + order + ")  ";
			g.drawString(orderString, x - metrics.stringWidth(orderString),
				p.y + metrics.getAscent() / 2);
		}
		g.dispose();
	}

	@Test
	public void testAutoMergeCodeUnits() {
		closeAllWindowsAndFrames();
		final MergeProgressPanel panel = new MergeProgressPanel();

		final String[] MEMORY = new String[] { "Memory" };
		final String[] PROGRAM_TREE = new String[] { "Program Tree" };
		final String[] DATA_TYPES = new String[] { "Data Types" };
		final String[] PROGRAM_CONTEXT = new String[] { "Program Context" };
		final String[] LISTING = new String[] { "Listing" };
		final String[] BYTES = new String[] { "Listing", "Bytes & Code Units" };
		final String[] FUNCTIONS = new String[] { "Listing", "Functions" };
		final String[] SYMBOLS = new String[] { "Listing", "Symbols" };
		final String[] COMMENTS = new String[] { "Listing",
			"Equates, User Defined Properties, References, Bookmarks & Comments" };
		final String[] EXTERNAL_PROGRAM = new String[] { "External Program" };
		final String[] PROPERTY_LIST = new String[] { "Property List" };

		panel.addInfo(MEMORY);
		panel.addInfo(PROGRAM_TREE);
		panel.addInfo(DATA_TYPES);
		panel.addInfo(PROGRAM_CONTEXT);
		panel.addInfo(LISTING);
		panel.addInfo(BYTES);
		panel.addInfo(FUNCTIONS);
		panel.addInfo(SYMBOLS);
		panel.addInfo(COMMENTS);
		panel.addInfo(EXTERNAL_PROGRAM);
		panel.addInfo(PROPERTY_LIST);

		runSwing(new Runnable() {

			@Override
			public void run() {
				panel.setCompleted(MEMORY);
				panel.setCompleted(PROGRAM_TREE);
				panel.setCompleted(DATA_TYPES);
				panel.setCompleted(PROGRAM_CONTEXT);
				panel.setCompleted(LISTING);
				panel.setCompleted(BYTES);
				panel.setInProgress(FUNCTIONS);
			}
		});

		JPanel mainPanel = new JPanel(new VerticalLayout(20));
		ImageIcon icon = ResourceManager.loadImage("images/Merge.png");
		JLabel topLabel =
			new JLabel("Merge of Byte * Code Unit changes", icon, SwingConstants.LEFT);
		mainPanel.add(topLabel);
		mainPanel.add(panel);
		JPanel progressPanel = new JPanel(new VerticalLayout(2));
		progressPanel.add(new JLabel("Progress In Current Phase"));
		JProgressBar progress = new JProgressBar(0, 100);
		progress.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 150));
		progress.setValue(22);
		progressPanel.add(progress);
		ImageIcon infoIcon = ResourceManager.loadImage("images/information.png");
		progressPanel.add(
			new JLabel("Finding conflicting code unit chagnes...", infoIcon, SwingConstants.LEFT));
		progressPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 100, 0));

		mainPanel.add(progressPanel);
		mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 10, 100, 10));

		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JButton apply = new JButton("Apply");
		JButton cancel = new JButton("Cancel");
		apply.setEnabled(false);
		buttonPanel.add(apply);
		buttonPanel.add(cancel);
		mainPanel.add(buttonPanel);

		JFrame frame = new JFrame();
		frame.setSize(800, 600);
		frame.setVisible(true);

		frame.getContentPane().setLayout(new BorderLayout());
		frame.getContentPane().add(mainPanel, BorderLayout.CENTER);
		frame.validate();
		frame.setTitle("Merge Tool");
		frame.setVisible(true);

		captureWindow(frame);
	}

	@Override
	// overridden so that we use the outer class's name when finding the help topic
	protected File getHelpTopic() {
		File helpTopicDir = getHelpTopicDir("Repository");
		assertNotNull("Unable to find help topic for test file: " + getClass().getName(),
			helpTopicDir);
		return helpTopicDir;
	}

}
