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
package ghidra.file.formats.android.art.headers;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.art.image_method.ImageMethod_Oreo;

/**
 * <a href="https://android.googlesource.com/platform/art/+/oreo-release/runtime/image.cc#28">oreo-release/runtime/image.c</a>
 */
public class ArtHeader_043 extends ArtHeader_030 {

	public ArtHeader_043(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public int getArtMethodCountForVersion() {
		return ImageMethod_Oreo.kImageMethodsCount.ordinal();
	}

}
