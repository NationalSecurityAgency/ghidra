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
package ghidra.pcodeCPort.slghsymbol;

import ghidra.pcodeCPort.sleighbase.*;
import ghidra.pcodeCPort.utils.*;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;


// A user-defined pcode-op
public class UserOpSymbol extends SleighSymbol {

	private int index;

	public UserOpSymbol(Location location) {
	    super(location);
	} // For use with restoreXml

	public UserOpSymbol( Location location, String nm ) {
		super( location, nm );
		index = 0;
	}

	public void setIndex( int ind ) {
		index = ind;
	}

	public int getIndex() {
		return index;
	}

	@Override
    public symbol_type getType() {
		return symbol_type.userop_symbol;
	}

	@Override
    public void saveXml( PrintStream s ) {
		s.append( "<userop" );
	    saveSleighSymbolXmlHeader(s);
		s.append( " index=\"" );
		s.print( index );
		s.print( "\"" );
		s.println( "/>" );
	}

	@Override
    public void saveXmlHeader( PrintStream s ) {
		s.append( "<userop_head" );
	    saveSleighSymbolXmlHeader(s);
		s.println( "/>" );
	}

	@Override
    public void restoreXml( Element el, SleighBase trans ) {
		index = XmlUtils.decodeUnknownInt( el.getAttributeValue( "index" ) );
	}

}
