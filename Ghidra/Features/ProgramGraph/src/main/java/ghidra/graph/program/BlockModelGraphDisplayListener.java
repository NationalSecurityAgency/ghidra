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
package ghidra.graph.program;

import java.util.*;

import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.service.graph.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GraphDisplayListener} that handle events back and from from program graphs.
 */
public class BlockModelGraphDisplayListener extends AddressBasedGraphDisplayListener {

	private CodeBlockModel blockModel;

	public BlockModelGraphDisplayListener(PluginTool tool, CodeBlockModel blockModel,
			GraphDisplay display) {
		super(tool, blockModel.getProgram(), display);
		this.blockModel = blockModel;
	}

	@Override
	public Address getAddress(AttributedVertex vertex) {
		return super.getAddress(vertex);
	}

	@Override
	protected String getVertexId(Address address) {
		try {
			CodeBlock[] blocks = blockModel.getCodeBlocksContaining(address, TaskMonitor.DUMMY);
			if (blocks != null && blocks.length > 0) {
				return super.getVertexId(blocks[0].getFirstStartAddress());
			}
		}
		catch (CancelledException e) {
			// Will not happen with dummyMonitor
			// Model has already done the work when the graph was created
		}
		return super.getVertexId(address);
	}

	@Override
	protected Set<AttributedVertex> getVertices(AddressSetView addrSet) {
		if (addrSet.isEmpty()) {
			return Collections.emptySet();
		}

		// Identify all blocks which have an entry point within the selection address set
		Set<AttributedVertex> vertices = new HashSet<>();
		try {
			addVerticesForAddresses(addrSet, vertices);
		}
		catch (CancelledException e) {
			// Will not happen with dummyMonitor
			// Model has already done the work when the graph was created
		}

		return vertices;
	}

	private void addVerticesForAddresses(AddressSetView addrSet, Set<AttributedVertex> vertices)
			throws CancelledException {

		SymbolTable symTable = program.getSymbolTable();
		CodeBlockIterator it =
			blockModel.getCodeBlocksContaining(addrSet, TaskMonitor.DUMMY);
		while (it.hasNext()) {
			CodeBlock block = it.next();
			String addrString;
			Address addr = block.getFirstStartAddress();
			if (addr.isExternalAddress()) {
				Symbol s = symTable.getPrimarySymbol(addr);
				addrString = s.getName(true);
			}
			else {
				addrString = addr.toString();
			}
			AttributedVertex vertex = graphDisplay.getGraph().getVertex(addrString);
			if (vertex != null) {
				vertices.add(vertex);
			}
		}
	}

	@Override
	protected AddressSet getAddresses(Set<AttributedVertex> vertices) {

		AddressSet addrSet = new AddressSet();
		try {
			// for each address string, translate it into a block
			//   and add it to the address set.
			for (AttributedVertex vertex : vertices) {
				addBlockAddresses(addrSet, vertex);
			}
		}
		catch (CancelledException e) {
			// Will not happen with dummyMonitor
			// Model has already done the work when the graph was created
		}
		return addrSet;
	}

	private void addBlockAddresses(AddressSet addrSet, AttributedVertex vertex)
			throws CancelledException {

		Address blockAddr = getAddress(vertex);
		if (!isValidAddress(blockAddr)) {
			return;
		}

		CodeBlock blocks[] = null;
		if (blockModel != null) {
			CodeBlock block = blockModel.getCodeBlockAt(blockAddr, TaskMonitor.DUMMY);
			if (block != null) {
				blocks = new CodeBlock[1];
				blocks[0] = block;
			}
			else {
				blocks = blockModel.getCodeBlocksContaining(blockAddr, TaskMonitor.DUMMY);
			}
		}
		if (blocks != null && blocks.length > 0) {
			for (CodeBlock block : blocks) {
				addrSet.add(block);
			}
		}
		else {
			addrSet.addRange(blockAddr, blockAddr);
		}
	}

	protected boolean isValidAddress(Address addr) {
		if (addr == null || program == null) {
			return false;
		}
		return program.getMemory().contains(addr) || addr.isExternalAddress();
	}

	@Override
	public GraphDisplayListener cloneWith(GraphDisplay newGraphDisplay) {
		return new BlockModelGraphDisplayListener(tool, blockModel, newGraphDisplay);
	}

}
