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
package ghidra.app.util.bin.format.macho.commands.dyld;

import java.io.File;
import java.util.List;

import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.Section;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.StringUtilities;

public class LazyBindState extends AbstractDyldInfoState {

	long lazyOffset;

	LazyBindState( MachHeader header, Program program ) {
		super( header, program );
	}

	public String print() {
		Address sectionAddress = getAddress();

		String sectionName = "no section";
		List<Section> sections = header.getAllSections();
		for ( Section section : sections ) {
			long start = section.getAddress();
			long end   = section.getAddress() + section.getSize();
			if ( sectionAddress.getOffset()  >= start && sectionAddress.getOffset() < end ) {
				sectionName = section.getSectionName();
			}
		}

		File file = new File( getOrdinalName( ) );

		StringBuffer buffer = new StringBuffer();
		buffer.append(  getSegmentName( ) );
		buffer.append( ' ' );
		buffer.append( ' ' );
		buffer.append(StringUtilities.pad(sectionName, ' ', -20));
		buffer.append( ' ' );
		buffer.append( ' ' );
		buffer.append( sectionAddress );
		buffer.append( ' ' );
		buffer.append( ' ' );
		buffer.append( Long.toHexString( lazyOffset ) );
		buffer.append( ' ' );
		buffer.append( ' ' );
		buffer.append(StringUtilities.pad(file.getName(), ' ', -20));
		buffer.append( ' ' );
		buffer.append( ' ' );
		buffer.append( symbolName );
		buffer.append( ' ' );
		buffer.append( ' ' );
		return buffer.toString();
	}

}
