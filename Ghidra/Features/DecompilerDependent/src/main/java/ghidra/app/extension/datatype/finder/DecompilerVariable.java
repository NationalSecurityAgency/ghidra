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
package ghidra.app.extension.datatype.finder;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;

/**
 * A base class that represents a variable from the decompiler.  This is either a variable 
 * type or a variable with an optional field access.
 */
public abstract class DecompilerVariable {

	protected List<DecompilerVariable> casts = new ArrayList<>();
	protected ClangToken variable;

	protected DecompilerVariable(ClangToken variable) {
		this.variable = variable;
	}

	public List<DecompilerVariable> getCasts() {
		return casts;
	}

	public DataType getParentDataType() {
		// this is really here for subclasses
		return getDataType();
	}

	public DataType getDataType() {
		if (variable instanceof ClangTypeToken) {
			return ((ClangTypeToken) variable).getDataType();
		}

// not sure if we need this; the type returned here is the structure and not the 
// field's type
//		if (variable instanceof ClangFieldToken) {
//			return ((ClangFieldToken) variable).getDataType();
//		}

		// Note: this is the icky part of the API.  How to know from where to get the data type?
		HighVariable highVariable = variable.getHighVariable();
		if (highVariable != null) {
			return highVariable.getDataType();
		}

		Varnode varnode = variable.getVarnode();
		DataType dataType = getDataType(varnode);
		if (dataType != null) {
			return dataType;
		}

		// The parent variable declaration node has the type
		ClangNode parent = variable.Parent();
		if (parent instanceof ClangVariableDecl) {
			ClangVariableDecl decl = (ClangVariableDecl) parent;
			dataType = decl.getDataType();
			if (dataType != null) {
				return dataType;
			}
		}

		// Prefer the type of the first input varnode, unless that type is a 'void *'.  
		// Usually, in that special case, the output varnode has the correct type information. 		
		PcodeOp op = variable.getPcodeOp();
		dataType = getInputDataType(op);

		if (dataType instanceof PointerDataType) {
			dataType = DecompilerReference.getBaseType(dataType);
			if (dataType instanceof VoidDataType) {
				// don't search for void
				dataType = null;
			}
		}

		if (dataType != null) {
			return dataType;
		}

		// Finally, try the output varnode
		dataType = getOutputDataType(op);
		return dataType;
	}

	private DataType getInputDataType(PcodeOp op) {
		if (op == null) {
			return null;
		}

		Varnode[] inputs = op.getInputs();
		if (inputs.length == 2) {
			return inputs[0].getHigh().getDataType();
		}

		return null;
	}

	private DataType getOutputDataType(PcodeOp op) {
		if (op == null) {
			return null;
		}

		Varnode output = op.getOutput();
		if (output == null) {
			// can happen when a variable in volatile memory is used in a write_volatile
			// pseudo operation
			return null;
		}

		HighVariable high = output.getHigh();
		if (high == null) {
			// not sure if this can happen; just in case
			return null;
		}

		return high.getDataType();
	}

	private DataType getDataType(Varnode varnode) {
		if (varnode != null) {
			HighVariable highVariable = varnode.getHigh();
			if (highVariable != null) {
				return highVariable.getDataType();
			}
		}
		return null;
	}

	public ClangNode getParent() {
		return variable.Parent();
	}

	public Function getFunction() {
		ClangFunction clangFunction = variable.getClangFunction();
		HighFunction highFunction = clangFunction.getHighFunction();
		Function function = highFunction.getFunction();
		return function;
	}

	public Address getAddress() {
		Address minAddress = variable.getMinAddress();
		if (minAddress != null) {
			return minAddress;
		}

		// Note: some variables do not have an address, such as function parameters.  In that
		//       case, we will walk backwards until we hit the function, using that address.
		ClangNode parent = variable.Parent();
		while (parent != null) {
			if (parent instanceof ClangFunction) {
				HighFunction highFunction = ((ClangFunction) parent).getHighFunction();
				Function function = highFunction.getFunction();
				Address entry = function.getEntryPoint();
				return entry;
			}

			Address parentAddress = parent.getMinAddress();
			if (parentAddress != null) {
				return parentAddress;
			}
			parent = parent.Parent();
		}

		return null;
	}

	public String getName() {
		String text = variable.getText();
		return text;
	}

	@Override
	public String toString() {
		String castString = casts.isEmpty() ? "" : "\tcasts: " + casts + ",\n";
		//@formatter:off
		return "{\n" +
			castString + 
			"\tvariable: " + variable + ",\n" +
		"}";
		//@formatter:on
	}
}
