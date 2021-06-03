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
package ghidra.pcodeCPort.pcoderaw;

import org.jdom.Element;

import ghidra.pcodeCPort.address.*;
import ghidra.pcodeCPort.error.*;
import ghidra.pcodeCPort.space.*;
import ghidra.pcodeCPort.translate.*;

public class VarnodeData {
	//  string name;			// This field will be depracated when sleigh comes on line
	public AddrSpace space;

	public long offset;

	public int size;
	// for use before restoreXML
	public VarnodeData() { 
	}
	public VarnodeData( AddrSpace base, long off, int size ) {
		space = base;
		offset = off;
		this.size = size;
	}

	@Override
	public boolean equals( Object obj ) {
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != VarnodeData.class) {
			return false;
		}
		VarnodeData other = (VarnodeData) obj;
		return space == other.space && offset == other.offset && size == other.size;
	}

	@Override
	public int hashCode() {
	    return space.hashCode() + (int) offset + size;
	}
	
	public int compareTo( VarnodeData other ) {
		int result = space.compareTo( other.space );
		if (result != 0) {
			return result;
		}
		result = AddressUtils.unsignedCompare( offset, other.offset );
		if (result != 0) {
			return result;
		}
		return other.size - size;// BIG sizes come first
	}
	
	// Build this VarnodeData from an \b \<addr\> tag
	// \param el is the parsed tag
	// \param trans is the relevant processor translator
	public void restoreXml( Element el, Translate trans ) {
		String name = el.getAttributeValue( "name" );
		if (name != null) {
			VarnodeData vdata = trans.getRegister( name );
			space = vdata.space;
			offset = vdata.offset;
			size = vdata.size;
			return;
		}

		
		String attributeValue = el.getAttributeValue( "space" );
		if ( attributeValue == null ) {
		    return;
		}
		
        space = trans.getSpaceByName( attributeValue );
		if (space == null) {
			throw new LowlevelError( "Unknown space name: " + attributeValue );
		}
		offset = AddrSpace.restore_xml_offset( el );
		size = AddrSpace.restore_xml_size( el );
	}


	public Address getAddress() {
//	    if ( space == null ) {
//	        return new Address( AddrSpace.MIN_SPACE, 0 );
//	    }
	    return new Address(this.space, this.offset);
	}
}
