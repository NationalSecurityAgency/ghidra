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
//Looks for already defined graphic image data in the program 
//and writes all selected images to a directory. 
//@category Images

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;

import org.apache.commons.io.FilenameUtils;

import generic.util.image.ImageUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataImage;
import ghidra.program.model.data.Resource;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.exception.CancelledException;

public class ExportImagesScript extends GhidraScript {

	@Override
	public void run() throws IOException, CancelledException {
		String programName = currentProgram.getName();
		File outDir = askDirectory("Select Image Save Directory", "Select");
		if (outDir == null || !outDir.isDirectory()) {
			return;
		}

		for (Data data : DefinedDataIterator.byDataType(currentProgram, currentSelection,
			dt -> dt instanceof Resource)) {
			Object val = data.getValue();
			if (val instanceof DataImage) {
				DataImage dataImg = (DataImage) val;
				String imageType = dataImg.getImageFileType();

				String outputName = programName + "_" + data.getLabel() + "_" +
					data.getAddress().toString() + "." + imageType;
				File outputFile = new File(outDir, outputName);

				println("Found " + imageType + " in program " + programName + " at address " +
					data.getAddressString(false, true));
				writeImageToFile(data, imageType, outputFile);
			}
		}
	}

	private void writeImageToFile(Data data, String imageType, File outputFile) throws IOException {
		DataImage image = (DataImage) data.getValue();
		if (image == null) {
			println("Found an image at " + data.getAddressString(false, true) +
				" but was unable to create an image from it");
			return;
		}
		ImageIcon icon = image.getImageIcon();
		BufferedImage buffy = ImageUtils.getBufferedImage(icon.getImage());
		boolean didWrite = ImageIO.write(buffy, imageType, outputFile);
		if (!didWrite) {
			// ie. because bmp doesn't support transparency
			outputFile = new File(outputFile.getParent(),
				FilenameUtils.removeExtension(outputFile.getName()) + ".png");
			didWrite = ImageIO.write(buffy, "PNG", outputFile);
		}
		if (!didWrite) {
			outputFile.delete();
		}
	}
}
