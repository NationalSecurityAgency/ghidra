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
package ghidra.app.plugin.prototype.debug;

import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.image.RenderedImage;
import java.io.File;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

import docking.*;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.TESTING,
	shortDescription = "Capture Screenshots",
	description = "Capture screen images and export to Portable Network Graphic (.PNG) format."
)
//@formatter:on
public class ScreenshotPlugin extends ProgramPlugin {
	public static final String NAME = "ScreenshotPlugin";

	private PluginTool tool;
	private DockingAction captureActiveWindowAction;
	private DockingAction captureToolFrameAction;
	private JFileChooser fileChooser;

	public ScreenshotPlugin(PluginTool tool) {
		super(tool, true, false);
		this.tool = tool;

		setupActions();
	}

	@Override
	public void init() {
		super.init();
	}

	@Override
	public void dispose() {
		super.dispose();
	}

	private void setupActions() {
		captureActiveWindowAction = new DockingAction("Capture Active Component", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				JFrame frame = tool.getToolFrame();
				DockingWindowManager winMgr = DockingWindowManager.getInstance(frame);
				Component activeComponent = winMgr.getActiveComponent();
				if (activeComponent == null) {
					tool.setStatusInfo("Error: No active window");
					return;
				}

				RenderedImage image = generateImage(activeComponent);

				String componentName =
					((DockableComponent) activeComponent).getComponentWindowingPlaceholder().getName();
				File file = getFile(componentName + ".png");

				if (file != null) {
					writeFile(image, file);
				}
			}
		};
		captureActiveWindowAction.setAddToAllWindows(true);
		captureActiveWindowAction.setDescription("Takes a screenshot of the active component provider and exports it to PNG format.");
		captureActiveWindowAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F11,
			InputEvent.ALT_DOWN_MASK));
		String group = "ScreenCapture";
		captureActiveWindowAction.setMenuBarData(new MenuData(new String[] {
			ToolConstants.MENU_TOOLS, captureActiveWindowAction.getName() }, group));
		tool.addAction(captureActiveWindowAction);

		captureToolFrameAction = new DockingAction("Capture Current Tool Frame", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				DockingWindowManager manager = DockingWindowManager.getActiveInstance();
				Window window = manager.getActiveWindow();

				RenderedImage image = generateImage(window);

				String title = getTitleForWindow(window);
				File file = getFile(title + ".png");
				if (file != null) {
					writeFile(image, file);
				}
			}
		};
		captureToolFrameAction.setAddToAllWindows(true);
		captureToolFrameAction.setDescription("Takes a screenshot of the active tool and exports it to PNG format.");
		captureToolFrameAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F12,
			InputEvent.ALT_DOWN_MASK));
		captureToolFrameAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS,
			captureToolFrameAction.getName() }, group));
		tool.addAction(captureToolFrameAction);
	}

	private String getTitleForWindow(Window window) {
		if (window instanceof JFrame) {
			return ((JFrame) window).getTitle();
		}
		else if (window instanceof JDialog) {
			return ((JDialog) window).getTitle();
		}
		return "Ghidra Window";
	}

	private File getFile(String fileName) {
		if (fileChooser == null) {
			fileChooser = new JFileChooser();
			fileChooser.setDialogType(JFileChooser.SAVE_DIALOG);
			fileChooser.setDialogTitle("Save Image");
			fileChooser.setFileFilter(new FileNameExtensionFilter("Portable Network Graphics",
				"png"));
		}

		File selectedFile = new File(fileName);
		fileChooser.setSelectedFile(selectedFile);
		if (fileChooser.showSaveDialog(tool.getToolFrame()) == JFileChooser.APPROVE_OPTION) {
			File file = fileChooser.getSelectedFile();
			if (file != null && !file.getName().endsWith(".png")) {
				// force the png extension
				return new File(file.getParentFile(), file.getName() + ".png");
			}
			return file;
		}

		return null;
	}

	private RenderedImage generateImage(Component component) {
		Rectangle r = component.getBounds();
		Image image = component.createImage(r.width, r.height);
		Graphics g = image.getGraphics();
		component.paint(g);

		return (RenderedImage) image;
	}

	private void writeFile(RenderedImage image, File selectedFile) {

		try {
			ImageIO.write(image, "png", selectedFile);
			tool.setStatusInfo("Captured tool to " + selectedFile.getCanonicalPath());
		}
		catch (Exception e) {
			tool.setStatusInfo("Error saving image: " + e);
		}
	}
}
