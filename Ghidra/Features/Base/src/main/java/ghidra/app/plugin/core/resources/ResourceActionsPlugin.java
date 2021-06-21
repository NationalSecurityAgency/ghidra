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
package ghidra.app.plugin.core.resources;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;

import org.apache.commons.io.FilenameUtils;

import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import generic.util.image.ImageUtils;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.viewer.field.ResourceFieldLocation;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.data.DataImage;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import utilities.util.FileUtilities;

/**
 * A plugin that adds actions to manage data resources in the listing
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Data resource actions",
	description = "This plugin provides actions related to embedded resources in the Listing."
)
//@formatter:on
public class ResourceActionsPlugin extends Plugin {
	public static final GhidraFileFilter GRAPHIC_FORMATS_FILTER =
		ExtensionFileFilter.forExtensions("Graphic Images", "png", "gif", "bmp", "jpg");

	public ResourceActionsPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();

		new ActionBuilder("Save Image New Format", getName())
				.withContext(ProgramLocationActionContext.class)
				.validContextWhen(plac -> plac.getLocation() instanceof ResourceFieldLocation &&
					((ResourceFieldLocation) plac.getLocation()).isDataImageResource())
				.onAction(
					plac -> saveImageAsNewImage((ResourceFieldLocation) plac.getLocation()))
				.popupMenuPath("Data", "Save Image", "As New Format")
				.buildAndInstall(tool);

		new ActionBuilder("Save Image Original Bytes", getName())
				.withContext(ProgramLocationActionContext.class)
				.validContextWhen(plac -> plac.getLocation() instanceof ResourceFieldLocation &&
					((ResourceFieldLocation) plac.getLocation()).isDataImageResource())
				.onAction(
					plac -> saveImageOriginalBytes((ResourceFieldLocation) plac.getLocation()))
				.popupMenuPath("Data", "Save Image", "Original Bytes")
				.buildAndInstall(tool);

		tool.setMenuGroup(new String[] { "Data", "Save Image" }, "A_save_image");

	}

	private void saveImageAsNewImage(ResourceFieldLocation imageLocation) {
		Data data = imageLocation.getResourceData();
		if (data == null || !(data.getValue() instanceof DataImage)) {
			return;
		}
		DataImage dataImage = (DataImage) data.getValue();
		GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setTitle("Save Image File As");
		chooser.setApproveButtonText("Save Image As");
		chooser.addFileFilter(GRAPHIC_FORMATS_FILTER);
		File f = chooser.getSelectedFile();
		if (f != null) {
			if (f.exists() && OptionDialog.showYesNoDialog(tool.getActiveWindow(),
				"Overwrite Existing File?",
				"Overwrite " + f.getName() + "?") != OptionDialog.YES_OPTION) {
				return;
			}
			String extension = FilenameUtils.getExtension(f.getName());
			if (extension.isBlank()) {
				Msg.showError(this, null, "Missing File Type",
					"Filename must specify a supported graphics format extension.");
				return;
			}

			try {
				ImageIcon icon = dataImage.getImageIcon();
				BufferedImage buffy = ImageUtils.getBufferedImage(icon.getImage());
				boolean success = ImageIO.write(buffy, extension, f);
				if (!success) {
					Msg.showError(this, null, "Image File Error",
						"Failed to save " + f.getName() +
							".\n\nEither unsupported image format or " +
							"incompatible image features with selected image format.");
					return;
				}
				tool.setStatusInfo(
					"Image resource at " + data.getAddress() + " saved as: " + f.getName());
			}
			catch (IOException e) {
				Msg.showError(this, null, "Image File Error", "Failed to save " + f.getName(), e);
			}
		}
	}

	private void saveImageOriginalBytes(ResourceFieldLocation imageLocation) {
		Data data = imageLocation.getResourceData();
		if (data == null) {
			return;
		}
		try {
			GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
			chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			chooser.setTitle("Save Image File As");
			chooser.setApproveButtonText("Save Image As");
			chooser.addFileFilter(GRAPHIC_FORMATS_FILTER);
			File f = chooser.getSelectedFile();
			if (f != null) {
				if (f.exists() && OptionDialog.showYesNoDialog(tool.getActiveWindow(),
					"Overwrite Existing File?",
					"Overwrite " + f.getName() + "?") != OptionDialog.YES_OPTION) {
					return;
				}
				byte[] bytes = data.getBytes();
				FileUtilities.writeBytes(f, bytes);
				tool.setStatusInfo(
					"Image resource at " + data.getAddress() + " saved as: " + f.getName());
			}
		}
		catch (MemoryAccessException | IOException e) {
			Msg.showError(this, null, "Error Saving Image File", "Failed to save image", e);
		}
	}
}
