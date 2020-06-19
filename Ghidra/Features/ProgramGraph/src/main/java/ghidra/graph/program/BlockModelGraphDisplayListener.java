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
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayListener;
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
	protected String getVertexIdForAddress(Address address) {
		try {
			CodeBlock[] blocks = blockModel.getCodeBlocksContaining(address, TaskMonitor.DUMMY);
			if (blocks != null && blocks.length > 0) {
				return super.getVertexIdForAddress(blocks[0].getFirstStartAddress());
			}
		}
		catch (CancelledException e) {
			// Will not happen with dummyMonitor
			// Model has already done the work when the graph was created
		}
		return super.getVertexIdForAddress(address);
	}

	@Override
	protected List<String> getVertices(AddressSetView addrSet) {
		if (addrSet.isEmpty()) {
			return Collections.emptyList();
		}

		// Identify all blocks which have an entry point within the selection address set
		ArrayList<String> blockList = new ArrayList<String>();
		try {
			SymbolTable symTable = program.getSymbolTable();
			CodeBlockIterator cbIter =
				blockModel.getCodeBlocksContaining(addrSet, TaskMonitor.DUMMY);
			while (cbIter.hasNext()) {
				CodeBlock block = cbIter.next();
				String addrString;
				Address addr = block.getFirstStartAddress();
				if (addr.isExternalAddress()) {
					Symbol s = symTable.getPrimarySymbol(addr);
					addrString = s.getName(true);
				}
				else {
					addrString = addr.toString();
				}
				blockList.add(addrString);
			}
		}
		catch (CancelledException e) {
			// Will not happen with dummyMonitor
			// Model has already done the work when the graph was created
		}

		return blockList;
	}

	@Override
	protected AddressSet getAddressSetForVertices(List<String> vertexIds) {
		AddressSet addrSet = new AddressSet();

		try {
			// for each address string, translate it into a block
			//   and add it to the address set.
			for (String vertexId : vertexIds) {
				Address blockAddr = getAddressForVertexId(vertexId);
				if (!isValidAddress(blockAddr)) {
					continue;
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
		}
		catch (CancelledException e) {
			// Will not happen with dummyMonitor
			// Model has already done the work when the graph was created
		}
		return addrSet;
	}

	protected boolean isValidAddress(Address addr) {
		if (addr == null || program == null) {
			return false;
		}
		return program.getMemory().contains(addr) || addr.isExternalAddress();
	}

}
