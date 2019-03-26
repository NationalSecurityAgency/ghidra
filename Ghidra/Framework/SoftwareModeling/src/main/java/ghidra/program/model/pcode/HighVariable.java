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

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * 
 *
 * A High-level variable (as in a high-level language like C/C++)
 * built out of Varnodes (low-level variables).  This is a base-class
 */
public abstract class HighVariable {

	private String name;
	private DataType type;
	private Varnode represent;		// A representative varnode
	private Varnode[] instances;	// Instances of this high-level variable
	private HighFunction function;	// associated function

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
		for(int i=0;i<instances.length;++i) {
			if (instances[i] instanceof VarnodeAST)
				((VarnodeAST)instances[i]).setHigh(this);
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
		else
			instances = inst;
	}

	public VariableStorage getStorage() {
		Program program = getHighFunction().getFunction().getProgram();
		try {
			if (represent != null && (represent.isAddress() || represent.isRegister())) {
				return new VariableStorage(program, represent);
			}
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Failed to define variable storage: " + this, e);
		}
		return VariableStorage.UNASSIGNED_STORAGE;
	}
}
