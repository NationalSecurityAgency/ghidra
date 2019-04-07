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
package ghidra.pcodeCPort.space;

import ghidra.pcodeCPort.translate.*;
import ghidra.pcodeCPort.utils.*;

import java.io.PrintStream;

import org.jdom.Element;



public class SpacebaseSpace extends AddrSpace {
	AddrSpace contain; // Containing space

	@Override
    public AddrSpace getContain() {
		return contain;
	}

	public SpacebaseSpace( String nm, int ind, int sz, AddrSpace base, int dl ) {
		super( base.getTrans(), spacetype.IPTR_SPACEBASE, nm, sz, base.getWordSize(), ind, 0, dl );
		contain = base;
	}

	public SpacebaseSpace( Translate t ) {
		super( t, spacetype.IPTR_SPACEBASE );
	}

	@Override
    public void saveXml( PrintStream s ) {
		s.print( "<space_base" );
		save_basic_attributes( s );
		XmlUtils.a_v( s, "contain", contain.getName() );
		s.println( "/>" );
	}

	@Override
    public void restoreXml( Element el ) {
		super.restoreXml( el ); // Restore basic attributes
		contain = getTrans().getSpaceByName( el.getAttributeValue( "contain" ) );
	}

}
