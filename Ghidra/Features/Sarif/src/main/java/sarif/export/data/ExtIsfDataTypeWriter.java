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
package sarif.export.data;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

import com.google.gson.JsonObject;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FactoryDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.ISF.IsfBuiltIn;
import ghidra.program.model.data.ISF.IsfDataTypeWriter;
import ghidra.program.model.data.ISF.IsfEnum;
import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.data.ISF.IsfTypedObject;
import ghidra.program.model.data.ISF.IsfTypedefBase;
import ghidra.program.model.data.ISF.IsfTypedefPointer;
import ghidra.program.model.data.ISF.IsfUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ExtIsfDataTypeWriter extends IsfDataTypeWriter {

	public ExtIsfDataTypeWriter(DataTypeManager dtm, List<DataType> target, Writer baseWriter) throws IOException {
		super(dtm, target, baseWriter);
		STRICT = false;
	}

	public JsonObject getRootObject(TaskMonitor monitor) throws CancelledException, IOException {
		genRoot(monitor);
		return root;
	}
	
	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		super.genRoot(monitor);
		data.add("functions", functions);
	}
	
	/**
	 * Writes the root type as ISF JSON using the underlying writer. For now, ignoring top-level
	 * bit-fields and function defs as unsupported by ISF. Typedefs really deserve their own
	 * category, but again unsupported.
	 * 
	 * @param dt the root type to write as ISF JSON
	 * @param monitor the task monitor
	 * @throws IOException if there is an exception writing the output
	 */
	@Override
	protected IsfObject getIsfObject(DataType dt, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (dt == null) {
			throw new IOException("Null datatype passed to getIsfObject");
		}
		if (dt instanceof FactoryDataType) {
			Msg.error(this, "Factory root types may not be written - type: " + dt);
		}
		if (dt instanceof BitFieldDataType) {
			Msg.error(this, "BitField data types may not be written - type: " + dt);
		}
		if (dt instanceof Pointer || dt instanceof Array) {
			IsfObject type = getObjectDataType(IsfUtilities.getBaseDataType(dt));
			IsfObject obj = new ExtIsfTypedObject(dt, type);
			return obj;
		}

		dt = dt.clone(dtm); // force resize/repack for target root organization

		IsfObject res = resolve(dt);
		if (res != null) {
			return res;
		}

		if (dt instanceof Dynamic dynamic) {
			DataType rep = dynamic.getReplacementBaseType();
			return rep == null ? null : getIsfObject(rep, monitor);
		}
		else if (dt instanceof BuiltInDataType builtin) {
			return new IsfBuiltIn(builtin);
		}
		else if (dt instanceof TypeDef typedef) {
			return getObjectTypeDef(typedef, monitor);
		}
		else if (dt instanceof Composite composite) {
			return new ExtIsfComposite(composite, this, monitor);
		}
		else if (dt instanceof Enum enumm) {
			return new IsfEnum(enumm);
		}
		else if (dt instanceof FunctionDefinition funcDef) {  
			return new ExtIsfFunction(funcDef);
		}
		else {
			Msg.warn(this, "Unable to write datatype. Type unrecognized: " + dt.getClass());
		}

		return null;
	}
	
	@Override
	public IsfTypedefBase newTypedefBase(TypeDef typeDef) {
		return new ExtIsfTypedefBase(typeDef);
	}

	@Override
	public IsfTypedefPointer newTypedefPointer(TypeDef typeDef) {
		return new ExtIsfTypedefPointer(typeDef);
	}

	public IsfObject newTypedefUser(TypeDef typeDef, IsfObject object) {
		return new ExtIsfTypedefUser(typeDef, object);
	}

	@Override
	public IsfTypedObject newTypedObject(DataType dt, IsfObject type) {
		return new ExtIsfTypedObject(dt, type);
	}

	@Override
	public IsfObject newIsfDynamicComponent(Dynamic dynamic, IsfObject type, int elementCnt) {
		return new ExtIsfDynamicComponent(dynamic, type, elementCnt);
	}


}
