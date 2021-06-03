/* ###
 * IP: GHIDRA
 * NOTE: Generated FILE!
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
package ghidra.app.util.cparser.C;

import ghidra.program.model.data.*;

/**
 * Container for information about a Declaration that is accumulated during parsing.
 */
public class Declaration {
	private int qualifier;
	private DataType dt;
	private String name;
	private String comment;
	private int bitSize = -1;
	private boolean flexArray = false;  // true if this is a zero size flex array component

	public Declaration() {
		super();
	}

	public Declaration(Declaration dec) {
		this();
		this.dt = dec.getDataType();
	}

	public Declaration(Declaration dec, String name) throws ParseException {
		this();
		if (dec == null) {
			throw new ParseException("Undefined data type \"" + name + "\"");
		}
		this.dt = dec.getDataType();
		this.name = name;
	}

	public Declaration(String name) {
		this.name = name;
	}

	public Declaration(DataType dt) {
		this();
		this.dt = dt;
	}

	public Declaration(Declaration subDecl, DataType dt) {
		this.dt = dt;
		if (subDecl == null) {
			return;
		}
		if (subDecl.dt != null && subDecl.dt instanceof PointerDataType) {
			this.dt = new PointerDataType(dt);
		}
		this.name = subDecl.name;
		this.comment = subDecl.comment;
	}

	public Declaration(DataType dt, String name) {
		this();
		this.dt = dt;
		this.name = name;
	}

	public Declaration(DataType dt, String name, String comment) {
		this();
		this.dt = dt;
		this.name = name;
		this.comment = comment;
	}

	public String getComment() {
		return comment;
	}

	public int getQualifier() {
		return qualifier;
	}

	public DataType getDataType() {
		return dt;
	}

	public String getName() {
		if (name == null) {
			return "";
		}
		return name;
	}

	public void setComment(String string) {
		comment = string;
	}

	public void setQualifier(int qualifier) {
		this.qualifier = qualifier;
	}

	public void setDataType(DataType type) {
		// apply any signed/unsigned modifier that may have come before
		if (dt instanceof AbstractIntegerDataType && type instanceof AbstractIntegerDataType) {
			AbstractIntegerDataType primDT = (AbstractIntegerDataType) dt;
			AbstractIntegerDataType primNewDT = (AbstractIntegerDataType) type;
			// if unsigned keyword came earlier and feeding a new signed type, must swap to unsigned
			//   else signed is the same.
			if (!primDT.isSigned() && primNewDT.isSigned()) {
				type = primNewDT.getOppositeSignednessDataType();
			}
		}
		dt = type;
	}

	public void setName(String string) {
		name = string;
	}

	/**
	 * @return true if a bitfield size has been set
	 */
	boolean isBitField() {
		return bitSize >= 0;
	}

	/**
	 * @return the currently set bitfield size
	 */
	public int getBitFieldSize() {
		return bitSize;
	}

	/**
	 * Set the bitfield size for this data type
	 * More checking could be done here if the bitfield is set on something that
	 * isn't a bitfield, but that probably isn't necessary.
	 * 
	 * @param bits number of bits in the bitfield
	 * @throws ParseException exception if bitfield to large for the current data type.
	 */
	void setBitFieldSize(int bits) throws ParseException {
		if (bits < 0) {
			throw new ParseException("Negative bitfield size not permitted: " + dt.getName());
		}
		bitSize = bits;
	}

	public void setFlexArray(boolean b) {
		flexArray = b;
	}

	public boolean isFlexArray() {
		return flexArray;
	}
}
