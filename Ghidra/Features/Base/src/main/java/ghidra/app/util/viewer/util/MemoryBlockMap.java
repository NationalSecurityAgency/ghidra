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
package ghidra.app.util.viewer.util;

import java.awt.Rectangle;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class MemoryBlockMap implements AddressPixelMap {

	private Program program;
	private MemoryBlock[] blocks;
	private float addressesPerPixel;
	private int[] pixels;

	public MemoryBlockMap(Program program) {
		this.program = program;
	}

	@Override
	public void createMapping(int width) {
		if (width <= 0) {
			return;
		}

		blocks = program.getMemory().getBlocks();
		pixels = new int[blocks.length];
		long totalSize = 0;
		for (MemoryBlock block : blocks) {
			totalSize += block.getSize();
		}
		addressesPerPixel = (float) totalSize / (float) width;
		for (int i = 0; i < blocks.length; i++) {
			pixels[i] = Math.round(blocks[i].getSize() / addressesPerPixel);
		}
	}

	@Override
	public Address getAddress(int pixel) {
		if (pixels == null) {
			return null;
		}

		try {
			int curPos = 0;
			for (int i = 0; i < pixels.length; i++) {
				int curSize = pixels[i];
				if (curPos + curSize > pixel) {
					return blocks[i].getStart().add(
						Math.round((pixel - curPos) * addressesPerPixel));
				}
				curPos += curSize;
			}
		}
		catch (Exception e) {
		}

		return null;
	}

	@Override
	public int getPixel(Address address) {
		if (address == null || pixels == null || blocks == null) {
			return -1;
		}

		int curPixel = 0;
		for (int i = 0; i < blocks.length; i++) {
			MemoryBlock block = blocks[i];
			if (block.contains(address)) {
				long offset = address.subtract(block.getStart());
				return curPixel + Math.round(offset / addressesPerPixel);
			}
			curPixel += pixels[i];
		}
		return -1;
	}

	@Override
	public MemoryBlock[] getBlocks() {
		return blocks;
	}

	@Override
	public Rectangle getBlockPosition(MemoryBlock block) {
		int x = 0;
		for (int i = 0; i < blocks.length; i++) {
			if (block == blocks[i]) {
				return new Rectangle(x, 0, pixels[i], 0);
			}
			x += pixels[i];
		}

		return null;
	}

	@Override
	public void clear() {
		blocks = null;
		pixels = null;
	}

}
