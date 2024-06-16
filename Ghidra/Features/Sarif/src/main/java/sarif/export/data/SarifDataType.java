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

import ghidra.program.model.data.ISF.IsfBuiltIn;
import ghidra.program.model.data.ISF.IsfComposite;
import ghidra.program.model.data.ISF.IsfDataTypeWriter;
import ghidra.program.model.data.ISF.IsfEnum;
import ghidra.program.model.data.ISF.IsfFunction;
import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.data.ISF.IsfTypedObject;
import ghidra.program.model.data.ISF.IsfTypedefBase;
import ghidra.program.model.data.ISF.IsfTypedefPointer;
import ghidra.program.model.data.ISF.IsfTypedefUser;
import sarif.export.SarifObject;
import sarif.managers.DataTypesSarifMgr;

public class SarifDataType extends SarifObject {
	
	public SarifDataType(IsfObject obj, IsfDataTypeWriter writer) {
		super("DataType", DataTypesSarifMgr.KEY, writer.getTree(obj));
		message.addProperty("text", objToMessage(obj));
	}

	private String objToMessage(IsfObject obj) {
		if (obj instanceof IsfComposite) {
			return ((IsfComposite) obj).kind.equals("struct") ? "DT.Struct" : "DT.Union";
		}
		if (obj instanceof IsfEnum) {
			return "DT.Enum";
		}
		if (obj instanceof IsfFunction) {
			return "DT.Function";
		}
		if (obj instanceof IsfTypedefBase ||
			//obj instanceof IsfTypedefIntegral ||
			obj instanceof IsfTypedefPointer ||
			obj instanceof IsfTypedefUser) {
			return "DT.Typedef";
		}
		if (obj instanceof IsfTypedObject) {
			return "DT.TypedObject";
		}
		if (obj instanceof IsfBuiltIn) {
			return "DT.Builtin";
		}
		return "DT.Base";
	}

}
