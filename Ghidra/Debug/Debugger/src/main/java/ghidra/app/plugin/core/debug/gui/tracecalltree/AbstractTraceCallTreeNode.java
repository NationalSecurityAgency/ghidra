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
package ghidra.app.plugin.core.debug.gui.tracecalltree;

import java.util.List;

import docking.widgets.gtreetable.GTreeTableNode;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.NumericUtilities;
import resources.Icons;

public abstract class AbstractTraceCallTreeNode extends GTreeTableNode {
	public record ParamNameToBytes(String name, byte[] bytes) {}

	private final TraceSnapshot snap;
	private final List<ParamNameToBytes> parameters;
	private final byte[] returnVal;
	private final String module;
	private int largestParamSize = 0;

	public AbstractTraceCallTreeNode(final String name, final String module,
			final TraceSnapshot snap, List<ParamNameToBytes> parameters, final byte[] returnVal) {
		super(name);
		icon = Icons.RIGHT_ICON;
		this.snap = snap;
		this.parameters = parameters;
		this.returnVal = returnVal;
		this.module = module;
	}

	public int getLargestParamSize() {
		return largestParamSize;
	}

	public String getModule() {
		return module;
	}

	public ParamNameToBytes getParameter(int i) {
		if ((parameters != null) && (i >= 0) && (i < parameters.size())) {
			return parameters.get(i);
		}
		return null;
	}

	public int getParameterNumber() {
		return parameters.size();
	}

	public List<ParamNameToBytes> getParameters() {
		return parameters;
	}

	public String getParameterString(int i) {
		if ((parameters != null) && (i >= 0) && (i < parameters.size())) {
			return "%s: %s".formatted(parameters.get(i).name,
				NumericUtilities.convertBytesToString(parameters.get(i).bytes));
		}
		return "";
	}

	public byte[] getReturnVal() {
		return returnVal;
	}

	public String getReturnValString() {
		if (returnVal == null) {
			return "";
		}
		return "Return: %s".formatted(NumericUtilities.convertBytesToString(returnVal));
	}

	public long getSnapshotKey() {
		if (snap == null) {
			return -1;
		}
		return snap.getKey();
	}

	@Override
	public String getTreeData() {
		return name;
	}

	public void setLargestParamSize(int largestParamSize) {
		this.largestParamSize = largestParamSize;
	}
}
