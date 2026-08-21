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
package ghidra.app.plugin.core.decompiler.taint.slicetree;

import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.Icon;

import ghidra.app.plugin.core.decompiler.taint.TaintSliceTreeProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * For this plugin there are two trees side by side.
 * This tree is on the left.  This node is the "root" or at the top of the tree.  All nodes that flow from it
 * are actually HIGHER up in the call stack to get to this node. They are nodes that CALL INTO this node via
 * some call path.
 */
public class InSliceRootNode extends InSliceNode {

	public InSliceRootNode(Program program, Function function, Address sourceAddress,
			boolean filterDuplicates, AtomicInteger filterDepth) {
		super(program, function, sourceAddress, filterDuplicates, filterDepth);
		name = function.getName();
	}

	@Override
	public SliceNode recreate() {
		return new InSliceRootNode(program, function, getSourceAddress(), filterDuplicates,
			filterDepth);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return TaintSliceTreeProvider.TAINT_ICON;
	}

	@Override
	public String getName() {
		return "Backward Taint from " + name;
	}
}
