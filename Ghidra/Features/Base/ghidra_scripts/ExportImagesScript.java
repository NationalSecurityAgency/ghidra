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
//Looks for defined image data in the program 
//and writes out any images to the directory 
//where the executable is stored
//@category Images

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;

import generic.util.image.ImageUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

public class ExportImagesScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		Listing listing = currentProgram.getListing();
		DataIterator dataIt = listing.getDefinedData(true);
		while (dataIt.hasNext() && !monitor.isCancelled()) {
			Data data = dataIt.next();
			String execPath = currentProgram.getExecutablePath();
			String imagePath = execPath.substring(0, execPath.lastIndexOf(File.separator) + 1);
			String execName = execPath.substring(execPath.lastIndexOf(File.separator) + 1);
			String filename = imagePath + execName;

			checkDataForImage(data, filename);
		}
	}

	private void checkDataForImage(Data data, String filename) throws IOException {
		DataType dataType = data.getDataType();
		String imageType = null;

		if (data.getMnemonicString().equals("PNG")) {
			println("Found PNG in program " + currentProgram.getExecutablePath() + " at address " +
				data.getAddressString(false, true));
			filename += "_" + data.getLabel() + "_" + data.getAddress().toString() + ".png";
			imageType = "PNG";
		}
		else if (data.getMnemonicString().equals("GIF")) {
			println("Found GIF in program " + currentProgram.getExecutablePath() + " at address " +
				data.getAddressString(false, true));
			filename += "_" + data.getLabel() + "_" + data.getAddress().toString() + ".gif";
			imageType = "GIF";
		}
		else if (dataType instanceof BitmapResourceDataType) {
			println("Found BMP in program " + currentProgram.getExecutablePath() + " at address " +
				data.getAddressString(false, true));
			filename += "_" + data.getLabel() + "_" + data.getAddress().toString() + ".bmp";
			imageType = "BMP";
		}
		if (imageType != null) {
			writeImageToFile(data, imageType, filename);
		}
	}

	private void writeImageToFile(Data data, String imageType, String filename) throws IOException {
		DataImage image = (DataImage) data.getValue();
		if (image == null) {
			println("Found an image at " + data.getAddressString(false, true) +
				" but was unable to create an image from it");
			return;
		}
		ImageIcon icon = image.getImageIcon();
		BufferedImage buffy = ImageUtils.getBufferedImage(icon.getImage());
		File imageFile = new File(filename);
		boolean didWrite = ImageIO.write(buffy, imageType, imageFile);
		if (!didWrite) {
			didWrite = ImageIO.write(buffy, "PNG", imageFile);
		}
		if (!didWrite) {
			imageFile.delete();
		}
	}
}
