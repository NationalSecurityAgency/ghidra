/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.macos.asd;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macos.rm.ResourceHeader;

import java.io.IOException;

public final class EntryFactory {

	public final static Object getEntry(BinaryReader reader, EntryDescriptor descriptor) throws IOException {
		long oldIndex = reader.getPointerIndex();
		try {
			reader.setPointerIndex(descriptor.getOffset());
			switch (descriptor.getEntryID()) {
				case EntryDescriptorID.ENTRY_RESOURCE_FORK:
					return new ResourceHeader(reader, descriptor);
				default:
					return null;
			}
		}
		finally {
			reader.setPointerIndex(oldIndex);
		}
	}
}
