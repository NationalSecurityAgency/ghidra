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
package ghidra.pcodeCPort.semantics;

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.pcodeCPort.opcodes.*;
import ghidra.pcodeCPort.translate.*;
import ghidra.sleigh.grammar.*;

import java.io.*;
import java.util.*;


import org.jdom.*;


public class OpTpl {
    public final Location location;

	private VarnodeTpl output;
	private OpCode opc;
	private VectorSTL<VarnodeTpl> input = new VectorSTL<VarnodeTpl>();

	public OpTpl(Location location) {
	    this.location = location;
	}

	public OpTpl( Location location, OpCode oc ) {
	    this.location = location;
		opc = oc;
		output = null;
	}

	@Override
	public String toString() {
		return "OpTpl[opcode=" + opc + "]";
	}
	
	public VarnodeTpl getOut() {
		return output;
	}

	public int numInput() {
		return input.size();
	}

	public VarnodeTpl getIn( int i ) {
		return input.get( i );
	}

	public OpCode getOpcode() {
		return opc;
	}

	public void setOpcode( OpCode o ) {
		opc = o;
	}

	public void setOutput( VarnodeTpl vt ) {
		output = vt;
	}

	public void clearOutput() {
		output.dispose();
		output = null;
	}

	public void addInput( VarnodeTpl vt ) {
		input.push_back( vt );
	}

	public void setInput( VarnodeTpl vt, int slot ) {
		input.set( slot, vt );
	}

	// An OpTpl owns its varnode_tpls
	public void dispose() {
		if ( output != null ) {
			output.dispose();
		}
		IteratorSTL<VarnodeTpl> iter;
		for ( iter = input.begin(); !iter.isEnd(); iter.increment() )
			iter.get().dispose();
	}

	// Return if any input or output has zero size
	public boolean isZeroSize() {
		if ( output != null ) {
			if ( output.isZeroSize() )
				return true;
		}
		IteratorSTL<VarnodeTpl> iter;
		for ( iter = input.begin(); !iter.isEnd(); iter.increment() )
			if ( iter.get().isZeroSize() )
				return true;
		return false;
	}

	// Remove the indicated input
	public void removeInput( int index ) {
		input.get( index ).dispose();
		input.erase( index );
	}

	public void changeHandleIndex( VectorSTL<Integer> handmap ) {
		if ( output != null ) {
			output.changeHandleIndex( handmap );
		}
		IteratorSTL<VarnodeTpl> iter;
		for ( iter = input.begin(); !iter.isEnd(); iter.increment() )
			iter.get().changeHandleIndex( handmap );
	}

	public void saveXml( PrintStream s ) {
		s.append( "<op_tpl code=\"" );
		s.append( OpCode.get_opname( opc ) );
		s.append( "\">" );
		if ( output == null )
			s.append( "<null/>\n" );
		else
			output.saveXml( s );
		for ( int i = 0; i < input.size(); ++i )
			input.get( i ).saveXml( s );
		s.append( "</op_tpl>\n" );
	}

	public void restoreXml( Element el, Translate trans ) {
		opc = OpCode.get_opcode( el.getAttributeValue( "code" ) );
		List<?> list = el.getChildren();
		Iterator<?> iter = list.iterator();
		Element child = (Element) iter.next();
		if ( child.getName().equals( "null" ) )
			output = null;
		else {
			output = new VarnodeTpl(null);
			output.restoreXml( child, trans );
		}
		while ( iter.hasNext() ) {
			child = (Element) iter.next();
			VarnodeTpl vn = new VarnodeTpl(null);
			vn.restoreXml( child, trans );
			input.push_back( vn );
		}
	}

}
