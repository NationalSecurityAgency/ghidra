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
package ghidra.program.model.data;

import java.io.IOException;

import ghidra.program.model.mem.MemBuffer;

public class IconResource extends BitmapResource {

	public IconResource(MemBuffer buf) throws IOException {
		super(buf);
	}

	@Override
	public int getHeight() {
		return height / 2;
	}

	public int getImageDataSize() {
		return getComputedUncompressedImageDataSize();
	}

	/**
	 * @return int size of mask section in bytes
	 */
	@Override
	public int getMaskLength() {

		// each mask line is padded to fall on a 4 byte boundary
		int lineLen = ((((getWidth() + 7) / 8) + 3) / 4) * 4;

		int masklen = lineLen * getHeight();

		return masklen;
	}
}
