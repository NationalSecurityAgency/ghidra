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
package docking.widgets.imagepanel.actions;

import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;

import docking.ActionContext;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.imagepanel.ImagePanel;
import generic.util.image.ImageUtils;
import ghidra.util.Msg;
import resources.ResourceManager;

/**
 * An action to save the image from a NavigableImagePanel to a file.
 * <p>
 * The user is asked to provide a file to save the image to.
 * <p>
 * This class uses the ImageIO library to write the image to a file;
 * the image format is determined by filename extension -- PNG, GIF and JPG extensions are 
 * recognized and honored, other extensions are ignored, and the file is written in PNG 
 * format. Image transparency is honored when possible.
 * 
 * @see javax.imageio.ImageIO
 * 
 */
public class SaveImageAction extends ImagePanelDockingAction {

	public SaveImageAction(String owner, ImagePanel imagePanel) {
		super("Export Image", owner, imagePanel);

		setPopupMenuData(new MenuData(new String[] { "Export Image As..." }, "io"));
		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/disk_save_as.png")));

	}

	private static File getExportFile() {

		GhidraFileChooser chooser = new GhidraFileChooser(null);
		chooser.setTitle("Export Image As...");
		chooser.setApproveButtonText("Save As");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setMultiSelectionEnabled(false);

		File selected = chooser.getSelectedFile(true);

		if (chooser.wasCancelled()) {
			return null;
		}

		return selected;

	}

	private static String getExtensionFromFile(File file) {
		String name = file.getName();
		int extPos = name.lastIndexOf('.');
		if (extPos < 0) {
			return "png";
		}
		return name.substring(extPos);

	}

	private void exportImage(Image image, File file) throws IOException {

		BufferedImage buffered = ImageUtils.getBufferedImage(image);

		String extension = getExtensionFromFile(file).toLowerCase();

		switch (extension) {
			case "png":
			case "gif":
			case "jpg":
				break;
			default:
				extension = "png";
		}

		ImageIO.write(buffered, extension, file);
		Msg.info(this, "Saved image to '" + file.getCanonicalPath() + "' in " +
			extension.toUpperCase() + " format");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		File file = null;
		Image image = imagePanel.getImage();

		file = getExportFile();
		if (file == null) {
			return;
		}
		try {
			exportImage(image, file);
		}
		catch (IOException ioe) {
			Msg.error(this, "Unable to save image to '" + file.getName() + "': " + ioe.getMessage(),
				ioe);
		}

	}

}
