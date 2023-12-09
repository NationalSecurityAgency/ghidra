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
package sarif.handlers.result.sample;

import java.util.ArrayList;
import java.util.List;

import com.contrastsecurity.sarif.ReportingDescriptor;
import com.contrastsecurity.sarif.ReportingDescriptorReference;
import com.contrastsecurity.sarif.ToolComponent;

import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongDoubleDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramTask;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import sarif.handlers.SarifResultHandler;
import sarif.view.SarifResultsTableProvider;

public class SarifReturnTypeResultHandler extends SarifResultHandler  {
	
	@Override
	public String getKey() {
		return "return type";
	}

	@Override
	public String parse() {
		ToolComponent tc = df.getComponentMap().get(getKey());
		ReportingDescriptorReference ref = df.getTaxa().get(getKey());
		if (tc != null) {
			List<ReportingDescriptor> view = new ArrayList<>(tc.getTaxa());
			if (ref != null) {
				int index = ref.getIndex().intValue();
				if (index < view.size()) {
					return view.get(index).getId();
				}
			}
		}
		return null;
	}
	
	@Override
	public String getActionName() {
		return "Commit";
	}

	@Override
	public ProgramTask getTask(SarifResultsTableProvider provider) {
		return new ReturnTypeTaxonomyTask(provider);
	}
	
	private class ReturnTypeTaxonomyTask extends ProgramTask {

		private SarifResultsTableProvider provider;

		protected ReturnTypeTaxonomyTask(SarifResultsTableProvider provider) {
			super(provider.getController().getProgram(), "ReturnTypeTaxonomyTask", true, true, true);
			this.provider = provider;
		}
		
		protected void doRun(TaskMonitor monitor) {
			int col = provider.getIndex("return type");
			int[] selected = provider.filterTable.getTable().getSelectedRows();
			for (int row : selected) {
				Function func = provider.getController().getProgram().getFunctionManager()
						.getFunctionContaining(provider.model.getAddress(row));
				String value = (String) provider.getValue(row, col);
				setReturnType(func, value);
			}
		}
		
		private boolean setReturnType(Function func, String type)  {
			if (type != null) {
				try {
					func.setReturnType(parseDataType(type), func.getSignatureSource());
					return true;
				} catch (InvalidInputException e) {
					throw new RuntimeException("Error setting return type for "+func);
				}
			}
			return false;
		}
		
		private DataType parseDataType(String datatype) {
			switch (datatype) {
			case "int":
				return new IntegerDataType();
			case "uint":
			case "__ssize_t":
				return new UnsignedIntegerDataType();
			case "bool":
				return new BooleanDataType();
			case "char":
				return new CharDataType();
			case "char *":
			case "FILE *":
			case "void *":
			case "whcar_t *":
			case "tm *":
				return new PointerDataType();
			case "void":
				return new VoidDataType();
			case "double":
				return new DoubleDataType();
			case "long":
				return new LongDataType();
			case "longdouble":
				return new LongDoubleDataType();
			case "ulong":
				return new UnsignedLongDataType();
			}
			return null;
		}

	}
}
