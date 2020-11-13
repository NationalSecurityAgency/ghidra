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
package ghidra.program.model.pcode;

import java.util.ArrayList;

import ghidra.program.model.data.DataType;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * A High-level variable (as in a high-level language like C/C++)
 * built out of Varnodes (low-level variables).  This is a base-class
 */
public abstract class HighVariable {

	protected String name;
	protected DataType type;
	protected Varnode represent;		// A representative varnode
	protected Varnode[] instances;		// Instances of this high-level variable
	protected int offset = -1;			// Offset (in bytes) into containing symbol (-1 indicates whole match)
	protected HighFunction function;	// associated function

	/**
	 * Constructor for use with restoreXml
	 * @param func is the HighFunction this variable belongs to
	 */
	protected HighVariable(HighFunction func) {
		function = func;
	}

	protected HighVariable(String nm, DataType tp, Varnode rep, Varnode[] inst, HighFunction func) {
		name = nm;
		type = tp;
		function = func;
		attachInstances(inst, rep);
	}

	/**
	 * Link Varnodes directly to this HighVariable
	 */
	protected void setHighOnInstances() {
		for (Varnode instance : instances) {
			if (instance instanceof VarnodeAST) {
				((VarnodeAST)instance).setHigh(this);
			}
		}
	}

	/**
	 * @return the high function associated with this variable.
	 */
	public HighFunction getHighFunction() {
		return function;
	}

	/**
	 * @return get the name of the variable
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return get the size of the variable
	 */
	public int getSize() {
		return represent.getSize();
	}

	/**
	 * @return get the data type attached to the variable
	 */
	public DataType getDataType() {
		return type;
	}

	/**
	 * @return get the varnode that represents this variable
	 */
	public Varnode getRepresentative() {
		return represent;
	}

	/**
	 * A variable can reside in different locations at various times.
	 * Get all the instances of the variable.
	 * 
	 * @return all the variables instances
	 */
	public Varnode[] getInstances() {
		return instances;
	}

	/**
	 * Retrieve any underlying HighSymbol
	 * @return the HighSymbol
	 */
	public abstract HighSymbol getSymbol();

	/**
	 * Get the offset of this variable into its containing HighSymbol.  If the value
	 * is -1, this indicates that this HighVariable matches the size and storage of the symbol.
	 * @return the offset
	 */
	public int getOffset() {
		return offset;
	}

	/**
	 * Attach an instance or additional location the variable can be found in.
	 * 
	 * @param inst varnode where variable can reside.
	 * @param rep location that variable comes into scope.
	 */
	public void attachInstances(Varnode[] inst, Varnode rep) {
		represent = rep;
		if (inst == null) {
			instances = new Varnode[1];
			instances[0] = rep;
		}
		else {
			instances = inst;
		}
	}

	/**
	 * Restore the data-type and the Varnode instances of this HighVariable.
	 * The "representative" Varnode is also populated.
	 * @param parser is the XML stream
	 * @param el is the root {@code <high>} tag
	 * @throws PcodeXMLException if the XML is not valid
	 */
	protected void restoreInstances(XmlPullParser parser, XmlElement el)
			throws PcodeXMLException {
		int repref = SpecXmlUtils.decodeInt(el.getAttribute("repref"));
		Varnode rep = function.getRef(repref);
		if (rep == null) {
			throw new PcodeXMLException("Undefined varnode reference");
		}

		type = null;

		ArrayList<Varnode> vnlist = new ArrayList<Varnode>();
		if (parser.peek().isStart()) {
			type = function.getDataTypeManager().readXMLDataType(parser);
		}

		if (type == null) {
			throw new PcodeXMLException("Missing <type> for HighVariable");
		}

		while (parser.peek().isStart()) {
			Varnode vn = Varnode.readXML(parser, function);
			vnlist.add(vn);
		}
		Varnode[] vnarray = new Varnode[vnlist.size()];
		vnlist.toArray(vnarray);
		attachInstances(vnarray, rep);
		setHighOnInstances();
	}

	/**
	 * Return true in when the HighVariable should be recorded (in the database) using dynamic storage
	 * rather than using the actual address space and offset of the representative varnode.  Dynamic storage
	 * is typically needed if the actual storage is ephemeral (in the unique space).
	 * @return true if this needs dynamic storage
	 */
	public boolean requiresDynamicStorage() {
		if (represent.isUnique()) {
			return true;		// Temporary Varnodes always need dynamic storage
		}
		if (represent.getAddress().isStackAddress() && !represent.isAddrTied()) {
			return true;
		}
		return false;
	}

	/**
	 * Restore this HighVariable from a {@code <high>} XML tag
	 * @param parser is the XML stream
	 * @throws PcodeXMLException if the XML is not valid
	 */
	public abstract void restoreXml(XmlPullParser parser) throws PcodeXMLException;
}
