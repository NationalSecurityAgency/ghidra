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
package ghidra.app.plugin.core.calltree;

import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.Icon;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class OutgoingCallsRootNode extends OutgoingCallNode {

	OutgoingCallsRootNode(Program program, Function function, Address sourceAddress,
			boolean filterDuplicates, AtomicInteger filterDepth) {
		super(program, function, sourceAddress, CallTreePlugin.FUNCTION_ICON, filterDuplicates,
			filterDepth);
	}

	@Override
	CallNode recreate() {
		return new OutgoingCallsRootNode(program, function, getSourceAddress(), filterDuplicates,
			filterDepth);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return CallTreePlugin.FUNCTION_ICON;
	}

	@Override
	public String getName() {
		return "Outgoing References - " + name;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	@Override
	public String getToolTip() {
		return null;
	}
}
