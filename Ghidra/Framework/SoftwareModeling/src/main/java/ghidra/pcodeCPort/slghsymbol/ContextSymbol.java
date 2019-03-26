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
import ghidra.pcodeCPort.slghpatexpress.*;
import ghidra.pcodeCPort.utils.*;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;


public class ContextSymbol extends ValueSymbol {

	private VarnodeSymbol vn;
	private int low, high; // into a varnode
	private boolean flow;

	public ContextSymbol(Location location) {
	    super(location);
	} // For use with restoreXml

	public VarnodeSymbol getVarnode() {
		return vn;
	}

	public int getLow() {
		return low;
	}

	public int getHigh() {
		return high;
	}

	public boolean isFlow() {
	    return flow;
	}

	@Override
    public symbol_type getType() {
		return symbol_type.context_symbol;
	}

	public ContextSymbol( Location location, String nm, ContextField pate, VarnodeSymbol v, int l, int h, boolean flow ) {
		super( location, nm, pate );
		vn = v;
		low = l;
		high = h;
		this.flow = flow;
	}

	@Override
    public void saveXml( PrintStream s ) {
		s.append( "<context_sym" );
		saveSleighSymbolXmlHeader(s);
		s.append( " varnode=\"0x" );
		s.append( Long.toHexString( vn.getId() ) );
		s.append( "\"" );
		s.append( " low=\"" );
		s.print( low );
		s.append( "\"" );
        s.append( " high=\"" );
        s.print( high );
        s.append( "\" flow=\"" );
        s.print( flow );
		s.println( "\">" );
		patval.saveXml( s );
		s.println( "</context_sym>" );
	}

	@Override
    public void saveXmlHeader( PrintStream s ) {
		s.append( "<context_sym_head" );
		saveSleighSymbolXmlHeader(s);
		s.println( "/>" );
	}

	@Override
    public void restoreXml( Element el, SleighBase trans ) {
		super.restoreXml( el, trans );

		int id = XmlUtils.decodeUnknownInt( el.getAttributeValue( "varnode" ) );
		vn = (VarnodeSymbol) trans.findSymbol( id );
		low = XmlUtils.decodeUnknownInt( el.getAttributeValue( "low" ) );
		high = XmlUtils.decodeUnknownInt( el.getAttributeValue( "high" ) );
	}

}
