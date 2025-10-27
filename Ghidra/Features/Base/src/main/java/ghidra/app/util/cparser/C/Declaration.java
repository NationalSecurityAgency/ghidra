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

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.AddressModel;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;

/**
 * Container for information about a Declaration that is accumulated during parsing.
 */
public class Declaration {
	private ArrayList<Integer> qualifierList;
	private DataType dt;
	private String name;
	private String comment;
	private int bitSize = -1;

	public Declaration() {
		super();
	}

	public Declaration(Declaration dec) {
		this();
		this.dt = dec.getDataType();
		if (dec.qualifierList != null) {
			this.qualifierList = new ArrayList<Integer>(dec.qualifierList);
		}
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
		if (subDecl.qualifierList != null) {
			this.qualifierList = new ArrayList<Integer>(subDecl.qualifierList);
		}
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

	public List<Integer> getQualifiers() {
		if (qualifierList == null) {
			return List.of();
		}
		return qualifierList;
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

	public void addQualifier(int qualifier) {
		if (qualifierList == null) {
			qualifierList = new ArrayList<Integer>();
		}
		qualifierList.add(qualifier);
	}

	public void addQualifiers(Declaration dec) {
		if (dec.qualifierList == null) {
			return;
		}
		if (qualifierList == null) {
			qualifierList = new ArrayList<Integer>();
		}
		qualifierList.addAll(dec.qualifierList);
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

	/**
	 * @return the near address model from the datatype or false if null
	 */
	public boolean isNear() {
		if ((dt == null) || (dt.getAddressModel() == null)) {
			return false;
		} else {
			return dt.getAddressModel().equals(AddressModel.near);
		}
	}

	/**
	 * @param isNear if true set, otherwise clear
	 */
	public void setNear(boolean isNear) {
		if (dt == null) {
			return;
		} else if (isNear) {
			dt.setAddressModel(AddressModel.near);
		} else {
			dt.setAddressModel(AddressModel.unknown);
		}
	}

	/**
	 * @return the far address model from the datatype or false if null
	 */
	public boolean isFar() {
		if ((dt == null) || (dt.getAddressModel() == null)) {
			return false;
		} else {
			return dt.getAddressModel().equals(AddressModel.far);
		}
	}

	/**
	 * @param isFar if true set, otherwise clear
	 */
	public void setFar(boolean isFar) {
		if (dt == null) {
			return;
		} else if (isFar) {
			dt.setAddressModel(AddressModel.far);
		} else {
			dt.setAddressModel(null);
		}
	}

	/**
	 * @return the huge address model from the datatype or false if null
	 */
	public boolean isHuge() {
		if ((dt == null) || (dt.getAddressModel() == null)) {
			return false;
		} else {
			return dt.getAddressModel().equals(AddressModel.huge);
		}
	}

	/**
	 * @param isHuge if true set, otherwise clear
	 */
	public void setHuge(boolean isHuge) {
		if (dt == null) {
			return;
		} else if (isHuge) {
			dt.setAddressModel(AddressModel.huge);
		} else {
			dt.setAddressModel(AddressModel.unknown);
		}
	}
}
