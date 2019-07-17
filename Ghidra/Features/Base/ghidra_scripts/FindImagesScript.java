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
//Finds PNG and GIF images and applies data type if not already applied
//@category Images
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.GifDataType;
import ghidra.program.model.data.PngDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.util.ArrayList;
import java.util.List;

public class FindImagesScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		int numValidImagesFound = 0;
		//Look for potential GIF images in binary using image header byte patterns
		println("Looking for GIF and PNG images in " + currentProgram.getName());
		List<Address> foundGIFS = scanForGIF87aImages();
		foundGIFS.addAll(scanForGIF89aImages());

		//Loop over all potential found GIFs
		for (int i = 0; i < foundGIFS.size(); i++) {
			boolean foundGIFImage = false;
			//See if already applied GIF
			Data data = getDataAt(foundGIFS.get(i));
			//If not already applied, try to apply GIF data type
			if (data == null) {
				println("Trying to apply GIF datatype at " + foundGIFS.get(i).toString());
				try {
					Data newGIF = createData(foundGIFS.get(i), new GifDataType());
					if (newGIF != null) {
						println("Applied GIF at " + newGIF.getAddressString(false, true));
						foundGIFImage = true;
					}
				}
				//If GIF does not apply correctly then it is not really a GIF data type
				catch (Exception e) {
					println("Invalid GIF at " + foundGIFS.get(i).toString());
				}
			}
			else if (data.getMnemonicString().equals("GIF")) {
				println("GIF already applied at " + data.getAddressString(false, true));
				foundGIFImage = true;
			}

			//print found message only for those that apply corrrectly or were already applied
			if (foundGIFImage) {
				println("Found GIF in program " + currentProgram.getExecutablePath() +
					" at address " + foundGIFS.get(i).toString());
				numValidImagesFound++;
			}

		}

		//Look for potential PNG images in binary using image header byte patterns
		List<Address> foundPNGS = scanForPNGs();

		//Loop over all potential found PNGs
		for (int i = 0; i < foundPNGS.size(); i++) {
			boolean foundPNGImage = false;
			//See if already applied PNG
			Data data = getDataAt(foundPNGS.get(i));

			//If not already applied, try to apply PNG data type
			if (data == null) {
				println("Trying to apply PNG datatype at " + foundPNGS.get(i).toString());
				try {
					Data newPNG = createData(foundPNGS.get(i), new PngDataType());
					if (newPNG != null) {
						println("Applied PNG at " + newPNG.getAddressString(false, true));
						foundPNGImage = true;
					}
				}
				//If PNG does not apply correctly then it is not really a PNG data type
				catch (Exception e) {
					println("Invalid PNG at " + foundPNGS.get(i).toString());
				}
			}
			else if (data.getMnemonicString().equals("PNG")) {
				println("PNG already applied at " + data.getAddressString(false, true));
				foundPNGImage = true;
			}

			//print found message only for those that apply corrrectly or were already applied
			if (foundPNGImage) {
				println("Found PNG in program " + currentProgram.getExecutablePath() +
					" at address " + foundPNGS.get(i).toString());
				numValidImagesFound++;
			}
		}
		if (numValidImagesFound == 0) {
			println("No PNG or GIF images found in " + currentProgram.getName());
			if (this.isRunningHeadless()) {
				currentProgram.setTemporary(true);
			}
		}

	}

	List<Address> scanForGIF87aImages() {

		byte gifBytes[] = new byte[6];
		gifBytes[0] = (byte) 0x47;
		gifBytes[1] = (byte) 0x49;
		gifBytes[2] = (byte) 0x46;
		gifBytes[3] = (byte) 0x38;
		gifBytes[4] = (byte) 0x37;
		gifBytes[5] = (byte) 0x61;

		List<Address> foundGIFS = scanForImages(gifBytes);
		return foundGIFS;
	}

	List<Address> scanForGIF89aImages() {

		byte gifBytes[] = new byte[6];
		gifBytes[0] = (byte) 0x47;
		gifBytes[1] = (byte) 0x49;
		gifBytes[2] = (byte) 0x46;
		gifBytes[3] = (byte) 0x38;
		gifBytes[4] = (byte) 0x39;
		gifBytes[5] = (byte) 0x61;

		List<Address> foundGIFS = scanForImages(gifBytes);
		return foundGIFS;
	}

	List<Address> scanForPNGs() {

		byte pngBytes[] = new byte[8];
		pngBytes[0] = (byte) 0x89;
		pngBytes[1] = (byte) 0x50;
		pngBytes[2] = (byte) 0x4e;
		pngBytes[3] = (byte) 0x47;
		pngBytes[4] = (byte) 0x0d;
		pngBytes[5] = (byte) 0x0a;
		pngBytes[6] = (byte) 0x1a;
		pngBytes[7] = (byte) 0x0a;

		List<Address> foundPNGs = scanForImages(pngBytes);
		return foundPNGs;

	}

	List<Address> scanForImages(byte[] imageBytes) {
		Memory memory = currentProgram.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();

		byte maskBytes[] = null;

		List<Address> foundImages = new ArrayList<Address>();

		for (int i = 0; i < blocks.length; i++) {
			if (blocks[i].isInitialized()) {
				Address start = blocks[i].getStart();
				Address found = null;
				while (true) {
					if (monitor.isCancelled()) {
						break;
					}
					found =
						memory.findBytes(start, blocks[i].getEnd(), imageBytes, maskBytes, true,
							monitor);
					if (found != null) {
						foundImages.add(found);
						start = found.add(1);
					}
					else
						break;
				}
			}
		}
		return foundImages;
	}
}
