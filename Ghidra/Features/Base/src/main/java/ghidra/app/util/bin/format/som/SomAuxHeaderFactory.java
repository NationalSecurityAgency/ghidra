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
package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * A class for reading/creating SOM auxiliary headers
 */
public class SomAuxHeaderFactory {

	public static SomAuxHeader readNextAuxHeader(BinaryReader reader) throws IOException {
		long origReaderIndex = reader.getPointerIndex();
		SomAuxId auxId = new SomAuxId(reader);
		reader.setPointerIndex(origReaderIndex);

		return switch (auxId.getType()) {
			case SomConstants.EXEC_AUXILIARY_HEADER:
				yield new SomExecAuxHeader(reader);
			case SomConstants.LINKER_FOOTPRINT:
				yield new SomLinkerFootprintAuxHeader(reader);
			case SomConstants.PRODUCT_SPECIFICS:
				yield new SomProductSpecificsAuxHeader(reader);
			default:
				yield new SomUnknownAuxHeader(reader);
		};
	}
}
