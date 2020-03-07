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
package ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;

/**
 * <code>VariableOffset</code> can be used as an operand or sub-operand representation
 * object.  The toString() method should be used to obtain the displayable representation
 * string.  This object is intended to correspond to a explicit or implicit register/stack 
 * variable reference.  If an offset other than 0 is specified, the original Scalar should
 * be specified.
 */
public class VariableOffset {

	private Variable variable;
	private long offset;
	private boolean indirect;
	private boolean dataAccess;
	private Object replacedElement;
	private boolean includeScalarAdjustment;

	/**
	 * Constructor for an implied variable reference.
	 * @param variable function variable
	 * @param offset offset into variable
	 * @param indirect if true and variable data-type is a pointer, the offset 
	 * is relative to underlying data-type of the pointer-type.  This should generally be
	 * true for register use which would contain a structure pointer not a structure instance,
	 * whereas it would be false for stack-references.
	 * @param dataAccess true if content of variable is being read and/or written
	 */
	public VariableOffset(Variable variable, long offset, boolean indirect, boolean dataAccess) {
		this.variable = variable;
		this.offset = offset;
		this.indirect = indirect;
		this.dataAccess = dataAccess;
	}

	/**
	 * Constructor for an explicit variable reference.
	 * @param ref the reference
	 * @param var the variable being referenced
	 */
	public VariableOffset(Reference ref, Variable var) {

		indirect = false;
		variable = var;
		if (variable == null) {
			throw new IllegalArgumentException("Variable reference not bound to a variable");
		}

		RefType rt = ref.getReferenceType();
		dataAccess = rt.isRead() || rt.isWrite();

		if (ref instanceof StackReference && variable.isStackVariable()) {
			offset = variable.getStackOffset();
			offset = ((StackReference) ref).getStackOffset() - variable.getStackOffset();
		}

	}

	/**
	 * Sets the original replaced sub-operand Scalar.
	 * @param s scalar
	 * @param includeScalarAdjustment if true scalar adjustment will be included 
	 * with object list or string representation
	 */
	public void setReplacedElement(Scalar s, boolean includeScalarAdjustment) {
		replacedElement = s;
		this.includeScalarAdjustment = includeScalarAdjustment;
	}

	/**
	 * Sets the original replaced sub-operand Register.
	 */
	public void setReplacedElement(Register reg) {
		replacedElement = reg;
	}

	/**
	 * Returns the Scalar or Register sub-operand replaced by this VariableOffset object.
	 * @return object or null
	 */
	public Object getReplacedElement() {
		return replacedElement;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		for (Object obj : getObjects()) {
			buf.append(obj.toString());
		}
		return buf.toString();
	}

	/**
	 * Returns the data type access portion of this variable offset as a string
	 * @return the text
	 */
	public String getDataTypeDisplayText() {
		List<Object> objects = getObjects(false);
		LabelString labelString = (LabelString) objects.get(0);
		return labelString.toString();
	}

	private List<Object> getObjects(boolean showScalarAdjustment) {

		DataType dt = variable.getDataType();
		StringBuffer name = new StringBuffer(variable.getName());

		long scalarAdjustment = 0;
		if (showScalarAdjustment && (replacedElement instanceof Scalar)) {
			Scalar s = (Scalar) replacedElement;
			scalarAdjustment = variable.isStackVariable() ? s.getSignedValue() : s.getValue();
			scalarAdjustment -= offset;
			if (variable.isStackVariable() || variable.isMemoryVariable()) {
				Address storageAddr = variable.getMinAddress();
				scalarAdjustment -= storageAddr.getOffset();
			}
		}

		long absOffset = offset < 0 ? -offset : offset;
		if (absOffset <= Integer.MAX_VALUE) {

			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}

			boolean displayAsPtr = false;
			if (indirect && (dt instanceof Pointer)) {
				dt = ((Pointer) dt).getDataType();
				displayAsPtr = true;
			}

			int intOff = (int) absOffset;
			while (intOff > 0 || (dataAccess && intOff == 0)) {

				if (dt instanceof TypeDef) {
					dt = ((TypeDef) dt).getBaseDataType();
				}
				if (dt instanceof Structure) {
					DataTypeComponent cdt = ((Structure) dt).getComponentAt(intOff);
					if (cdt == null || cdt.isBitFieldComponent()) {
						// NOTE: byte offset is insufficient to identify a specific bitfield
						break;
					}
					String fieldName = cdt.getFieldName();
					if (fieldName == null) {
						fieldName = cdt.getDefaultFieldName();
					}
					name.append(displayAsPtr ? "->" : ".");
					name.append(fieldName);
					intOff -= cdt.getOffset();
					dt = cdt.getDataType();
				}
				else if (dt instanceof Array) {
					Array a = (Array) dt;
					int elementLen = a.getElementLength();
					if (intOff >= a.getLength()) {
						break; // unexpected
					}
					int index = intOff / elementLen;
					if (displayAsPtr) {
						name.insert(0, '*');
					}
					name.append('[');
					name.append(Integer.toString(index));
					name.append(']');
					intOff -= index * elementLen;
					dt = a.getDataType();
				}
				else {
					break;
				}
				displayAsPtr = false;
			}
			absOffset = intOff;
		}

		List<Object> list = new ArrayList<>();
		list.add(new LabelString(name.toString(), LabelString.VARIABLE));

		if (absOffset != 0 || scalarAdjustment != 0) {
			long adjustedOffset = (offset < 0 ? -absOffset : absOffset) + scalarAdjustment;
			if (adjustedOffset < 0) {
				adjustedOffset = -adjustedOffset;
				list.add('-');
			}
			else {
				list.add('+');
			}
			list.add(new Scalar(32, adjustedOffset));
		}
		return list;
	}

	/**
	 * Get list of markup objects
	 * @return list of markup objects
	 */
	public List<Object> getObjects() {
		return getObjects(includeScalarAdjustment);
	}

	public Variable getVariable() {
		return variable;
	}

	public boolean isIndirect() {
		return indirect;
	}

	public boolean isDataAccess() {
		return dataAccess;
	}

	public long getOffset() {
		return offset;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (dataAccess ? 1231 : 1237);
		result = prime * result + (includeScalarAdjustment ? 1231 : 1237);
		result = prime * result + (indirect ? 1231 : 1237);
		result = prime * result + (int) (offset ^ (offset >>> 32));
		result = prime * result + ((replacedElement == null) ? 0 : replacedElement.hashCode());
		result = prime * result + ((variable == null) ? 0 : variable.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (obj == null) {
			return false;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		VariableOffset other = (VariableOffset) obj;
		if (dataAccess != other.dataAccess) {
			return false;
		}

		if (includeScalarAdjustment != other.includeScalarAdjustment) {
			return false;
		}

		if (indirect != other.indirect) {
			return false;
		}

		if (offset != other.offset) {
			return false;
		}

		if (!SystemUtilities.isEqual(replacedElement, other.replacedElement)) {
			return false;
		}

		if (!SystemUtilities.isEqual(variable, other.variable)) {
			return false;
		}

		return true;
	}
}
