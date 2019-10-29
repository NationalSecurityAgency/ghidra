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
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionListener;
import java.awt.geom.Ellipse2D;
import java.awt.image.RenderedImage;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;

import javax.imageio.ImageIO;
import javax.swing.*;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.*;
import ghidra.util.Msg;
import ghidra.util.bean.GGlassPane;
import ghidra.util.bean.GGlassPanePainter;
import resources.ResourceManager;

public class ImageDialogProvider extends DialogComponentProvider {
	private GGlassPane glassPane;

	private JLabel oldImageLabel;
	private JLabel newImageLabel;

	private File imageFile;
	private Image oldImage;
	private Image newImage;

	private JTextField textField;
	private ShapePainter dragShape;
	private Collection<ShapePainter> shapeList = new ArrayList<>();
	private JComboBox<String> shapeCombo;

	protected ImageDialogProvider(File imageFile, Image oldImage, Image newImage) {
		super("Help Snapshot");
		this.imageFile = imageFile;
		this.oldImage = oldImage;
		this.newImage = newImage;
		addWorkPanel(buildWorkPanel());
		addOKButton();
		setOkButtonText("Don't Save");
		if (imageFile != null) {
			addButton(buildSaveButton());
		}
		setupMouseListener();
		createActions();
		setRememberLocation(false);
		setRememberSize(false);
	}

	private JButton buildSaveButton() {
		JButton button = new JButton("Save");
		button.addActionListener(e -> {
			writeFile(newImage);
			close();
		});
		return button;
	}

	private void createActions() {
		DockingAction action = new DockingAction("Add", "Test") {

			@Override
			public void actionPerformed(ActionContext context) {
				if (dragShape != null) {
					dragShape.setColor(Color.green.brighter());
					shapeList.add(dragShape);
					dragShape = null;
					glassPane.repaint();
				}
			}
		};
		action.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/Plus.png")));
		addAction(action);

		action = new DockingAction("Write", "Test") {

			@Override
			public void actionPerformed(ActionContext context) {
				Msg.debug(this, "Just kidding...");
			}
		};
		action.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/pencil16.png")));
		addAction(action);
	}

	private void setupMouseListener() {
		newImageLabel.addMouseMotionListener(new MouseMotionListener() {

			private Point startDrag;
			private Point lastDrag;

			@Override
			public void mouseMoved(MouseEvent e) {
				textField.setText("x = " + e.getX() + ", y = " + e.getY());
				if (startDrag != null) {
					System.out.println("Drag ended");
					startDrag = null;
				}
			}

			@Override
			public void mouseDragged(MouseEvent e) {
				if (startDrag == null) {
					System.out.println("Drag started");
					startDrag = e.getPoint();
				}
				else {
					glassPane.removePainter(dragShape);
					lastDrag = e.getPoint();
					int x1 = Math.min(startDrag.x, lastDrag.x);
					int x2 = Math.max(startDrag.x, lastDrag.x);
					int y1 = Math.min(startDrag.y, lastDrag.y);
					int y2 = Math.max(startDrag.y, lastDrag.y);
					Point startPoint = new Point(x1, y1);
					int width = x2 - x1;
					int height = y2 - y1;
					startPoint =
						SwingUtilities.convertPoint(e.getComponent(), startPoint, glassPane);

					String selectedItem = (String) shapeCombo.getSelectedItem();
					if ("Rectangle".equals(selectedItem)) {
						Rectangle r = new Rectangle(startPoint, new Dimension(width, height));
						dragShape = new ShapePainter(r, Color.RED);
					}
					else if ("Oval".equals(selectedItem)) {
						Ellipse2D ellipse =
							new Ellipse2D.Double(startPoint.x, startPoint.y, width, height);
						dragShape = new ShapePainter(ellipse, Color.RED);
					}
					else if ("Arrow".equals(selectedItem)) {
						// TODO
					}

					glassPane.addPainter(dragShape);
				}
			}
		});

	}

	private JComponent buildWorkPanel() {
		shapeCombo = new GComboBox<>();
		shapeCombo.addItem("Rectangle");
		shapeCombo.addItem("Oval");
		shapeCombo.addItem("Arrow");

		JPanel jPanel = new JPanel(new BorderLayout());
		jPanel.add(shapeCombo, BorderLayout.NORTH);

		JPanel imagePanel = new JPanel(new BorderLayout());

		newImageLabel = new GIconLabel(new ImageIcon(newImage));
		newImageLabel.setOpaque(true);
		newImageLabel.setBackground(Color.BLACK);
		JPanel newLabelPanel = new JPanel(new BorderLayout());

		if (oldImage != null) {
			oldImageLabel = new GIconLabel(new ImageIcon(oldImage));
			oldImageLabel.setOpaque(true);
			oldImageLabel.setBackground(Color.BLACK);
		}
		else {
			oldImageLabel = new GLabel("     Old image not found     ");
		}

		newLabelPanel.add(createImageLabelComponent("New Image"), BorderLayout.NORTH);
		newLabelPanel.setBorder(BorderFactory.createLineBorder(Color.black, 20));
		newLabelPanel.add(newImageLabel, BorderLayout.CENTER);

		JPanel oldLabelPanel = new JPanel(new BorderLayout());
		oldLabelPanel.add(createImageLabelComponent("Old Image"), BorderLayout.NORTH);
		oldLabelPanel.setBorder(BorderFactory.createLineBorder(Color.black, 20));
		oldLabelPanel.add(oldImageLabel, BorderLayout.CENTER);

		imagePanel.add(oldLabelPanel, BorderLayout.WEST);
		imagePanel.add(newLabelPanel, BorderLayout.EAST);

		jPanel.add(imagePanel, BorderLayout.CENTER);

		textField = new JTextField();
		jPanel.add(textField, BorderLayout.SOUTH);

		return jPanel;
	}

	private JComponent createImageLabelComponent(String name) {
		JPanel panel = new JPanel();
		JLabel label = createNameLabel(name);
		panel.add(label);
		panel.setBackground(label.getBackground());
		return panel;
	}

	private JLabel createNameLabel(String name) {
		JLabel label = new GDHtmlLabel("<html><b><font color='yellow' size='8'>" + name);
		label.setOpaque(true);
		//	label.setForeground(Color.YELLOW);
		label.setBackground(Color.BLACK);
		label.setHorizontalTextPosition(SwingConstants.CENTER);
		return label;
	}

	@Override
	protected void dialogShown() {
		JRootPane rootPane = SwingUtilities.getRootPane(getComponent());

		Component glass = rootPane.getGlassPane();
		if (glass instanceof GGlassPane) {
			glassPane = (GGlassPane) glass;
		}
	}

	@Override
	protected void okCallback() {
		close();
	}

	private void writeFile(Image image) {
		try {
			ImageIO.write((RenderedImage) image, "png", imageFile);
			Msg.info(this, "Captured tool to " + imageFile.getCanonicalPath());
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error Writing Image File", e.getMessage(), e);
		}
	}

	private class ShapePainter implements GGlassPanePainter {
		private Shape shape;
		private Color color;

		ShapePainter(Shape shape, Color color) {
			this.shape = shape;
			this.color = color;

		}

		public void setColor(Color color) {
			this.color = color;
		}

		@Override
		public void paint(GGlassPane pane, Graphics graphics) {

			graphics.setColor(color);

			Graphics2D g2d = (Graphics2D) graphics;
			BasicStroke stroke = new BasicStroke(5.0f);
			g2d.setStroke(stroke);
			g2d.draw(shape);
		}
	}
}
