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
package ghidra.app.util.bin.format.macos.rm;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macos.cfm.CFragResource;

import java.io.IOException;

public final class ResourceTypeFactory {

	public final static Object getResourceObject(BinaryReader reader, ResourceHeader header, ResourceType resourceType) throws IOException {
		long oldIndex = reader.getPointerIndex();
		try {
			switch (resourceType.getType()) {
				case ResourceTypes.TYPE_CFRG:
				{
					ReferenceListEntry referenceListEntry = resourceType.getReferenceList().get(0);
					reader.setPointerIndex(header.getResourceDataOffset() + 
							   header.getEntryDescriptor().getOffset() + 
							   referenceListEntry.getDataOffset() + 
							   4);
					return new CFragResource(reader);
				}
				default:
					return null;
			}
		}
		finally {
			reader.setPointerIndex(oldIndex);
		}
	}
}
