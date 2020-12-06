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
package ghidra.app.plugin.core.memory;

import java.util.Collections;
import java.util.List;

import docking.widgets.OptionDialog;
import ghidra.app.cmd.memory.DeleteBlockCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;

/**
 * Helper class to make changes to memory blocks.
 */
class MemoryMapManager {

	private Program program;
	private MemoryMapPlugin plugin;
	private PluginTool tool;

	MemoryMapManager(MemoryMapPlugin plugin) {
		this.plugin = plugin;
		tool = plugin.getTool();
	}

	/**
	 * Split the block by creating the new block at newStart address.
	 * @param block block to split
	 * @param newStart start address of new block
	 * @param newBlockName new block name
	 * @return boolean true if the split was successful.
	 */
	void splitBlock(MemoryBlock block, Address newStart, String newBlockName) {

		SplitBlockCmd cmd = new SplitBlockCmd(block, newStart, newBlockName);
		if (!tool.execute(cmd, program)) {
			Msg.showError(getClass(), plugin.getMemoryMapProvider().getComponent(),
				"Split Block Failed", cmd.getStatusMsg());
		}
	}

	/**
	 * Callback for merging blocks of memory
	 */
	void mergeBlocks(List<MemoryBlock> blocks) {
		// need to order by start address
		Collections.sort(blocks, (b1, b2) -> b1.getStart().compareTo(b2.getStart()));
		if (!goodBlocks(blocks)) {
			return;
		}

		MergeBlocksCmd cmd = new MergeBlocksCmd(blocks);
		if (!tool.execute(cmd, program)) {
			Msg.showError(getClass(), plugin.getMemoryMapProvider().getComponent(),
				"Merge Blocks Failed", cmd.getStatusMsg());
		}
	}

	private void renameFragment(Address start, String name) {

		Listing listing = program.getListing();
		String[] treeNames = listing.getTreeNames();
		for (String treeName : treeNames) {
			boolean duplicate = false;
			int index = 0;

			ProgramFragment frag = listing.getFragment(treeName, start);
			do {
				try {
					frag.setName("Frag" + index + "-" + name);
					duplicate = false;
				}
				catch (DuplicateNameException exc) {
					duplicate = true;
				}
				index++;
			}
			while (duplicate);
		}
	}

	private boolean goodBlocks(List<MemoryBlock> blocks) {
		// check that blocks are contigous (no other blocks in between)
		//    throw error if blocks in between
		Class<?> bc = null;
		long space_size = 0;
		for (int i = 0; i < (blocks.size() - 1); i++) {
			MemoryBlock blockA = blocks.get(i);
			MemoryBlock blockB = blocks.get(i + 1);
			if (bc == null) {
				bc = blockA.getClass();
			}
			if (bc != blockA.getClass() || bc != blockB.getClass()) {
				Msg.showError(this, plugin.getMemoryMapProvider().getComponent(),
					"Merge Blocks Failed",
					"Can't merge blocks because all block types are not the same");
				return false;
			}

			// make sure that the block after the first block is the second block
			Address nextStart = blockA.getEnd();
			AddressSpace space = nextStart.getAddressSpace();
			if (space.isOverlaySpace()) {
				Msg.showError(this, plugin.getMemoryMapProvider().getComponent(),
					"Merge Blocks Failed", "Can't merge overlay blocks");
				return false;
			}

			Address blockBstart = blockB.getStart();
			if (!space.isSuccessor(nextStart, blockBstart)) {
				try {
					Address a = nextStart.addNoWrap(1);
					MemoryBlock b = program.getMemory().getBlock(a);
					if (b != null) {
						Msg.showError(this, plugin.getMemoryMapProvider().getComponent(),
							"Merge Blocks Failed",
							"Can't merge blocks because they are not contiguous");
						return false;
					}
					else if (blockA.getType() == MemoryBlockType.BIT_MAPPED) {
						Msg.showError(this, plugin.getMemoryMapProvider().getComponent(),
							"Merge Blocks Failed",
							"Can't merge Bit Memory Blocks because they do not\n" +
								"have successive block end and block start addresses.");
						return false;
					}

				}
				catch (AddressOverflowException e) {
				}
			}

			try {
				space_size += blockBstart.subtract(blockA.getEnd());
			}
			catch (IllegalArgumentException e) {
				Msg.showError(this, plugin.getMemoryMapProvider().getComponent(),
					"Merge Blocks Failed", e.getMessage(), e);
				return false;
			}
		}

		// check that this won't create a large area between the address spaces
		if (space_size > 4 * 1024 * 1024) {
			int option = OptionDialog.showOptionDialog(plugin.getMemoryMapProvider().getComponent(),
				"Merge Memory Blocks",
				"Merging these blocks will create " + space_size / 1024 +
					"K extra bytes in memory.\n" +
					"Do you really want to merge the selected Memory Block(s)?",
				"Merge Blocks", OptionDialog.QUESTION_MESSAGE);
			if (option == 0) {
				return false;
			}
		}
		return true;
	}

	void setProgram(Program program) {
		this.program = program;
	}

	/**
	 * Delete the list of memory blocks.
	 */
	void deleteBlocks(final List<MemoryBlock> blocks) {

		if (blocks == null || blocks.size() <= 0) {
			return;
		}

		StringBuffer blockNames = new StringBuffer();
		AddressSet set = new AddressSet();
		for (int i = 0; i < blocks.size(); i++) {
			MemoryBlock block = blocks.get(i);
			blockNames.append(block.getName());
			if (i < blocks.size() - 1) {
				blockNames.append(", ");
			}
			set.addRange(block.getStart(), block.getEnd());
		}
		String msg =
			"Do you really want to delete the Memory Block(s)\n" + "   " + blockNames + "  ?";
		Listing listing = program.getListing();
		InstructionIterator iter = listing.getInstructions(set, true);

		if (iter.hasNext()) {
			msg = "Code Units exist in selected block(s).\n" + "Do you want to continue?";
		}
		else {
			DataIterator dIter = listing.getDefinedData(set, true);
			if (dIter.hasNext()) {
				msg = "Code Units exist in selected block(s).\n" + "Do you want to continue?";
			}
		}

		int option = -1;

		option = OptionDialog.showOptionDialog(plugin.getMemoryMapProvider().getComponent(),
			"Delete Memory Block?", msg, "Yes", OptionDialog.QUESTION_MESSAGE);

		if (option == OptionDialog.CANCEL_OPTION) {
			return;
		}

		Address[] addresses = new Address[blocks.size()];
		for (int i = 0; i < blocks.size(); i++) {
			MemoryBlock block = blocks.get(i);
			addresses[i] = block.getStart();
		}
		DeleteBlockCmd cmd = new DeleteBlockCmd(addresses, command -> {
			// don't care
		});

		tool.executeBackgroundCommand(cmd, program);
	}

	private class SplitBlockCmd implements Command {

		private MemoryBlock block;
		private Address newStart;
		private String newBlockName;
		private String msg;

		SplitBlockCmd(MemoryBlock block, Address newStart, String newBlockName) {
			this.block = block;
			this.newStart = newStart;
			this.newBlockName = newBlockName;
		}

		@Override
		public boolean applyTo(DomainObject obj) {
			Program p = (Program) obj;
			Memory memory = p.getMemory();

			if (!p.hasExclusiveAccess()) {
				msg = "Exclusive access required";
				return false;
			}

			try {
				memory.split(block, newStart);
			}
			catch (MemoryBlockException e) {
				msg = e.getMessage();
				return false;
			}
			catch (IllegalArgumentException e) {
				msg = e.getMessage();
				return false;
			}
			catch (NotFoundException e) {
				msg = e.getMessage();
				return false;
			}
			catch (LockException e) {
				msg = e.getMessage();
				return false;
			}
			MemoryBlock newBlock = memory.getBlock(newStart);
			try {
				newBlock.setName(newBlockName);
			}
			catch (LockException e) {
				msg = e.getMessage();
				return false;
			}
			return true;
		}

		@Override
		public String getName() {
			return "Split Memory Block";
		}

		@Override
		public String getStatusMsg() {
			return msg;
		}
	}

	private class MergeBlocksCmd implements Command {

		private String msg;
		private List<MemoryBlock> blocks;

		MergeBlocksCmd(List<MemoryBlock> blocks) {
			this.blocks = blocks;
		}

		@Override
		public boolean applyTo(DomainObject obj) {
			Program p = (Program) obj;
			Memory mem = p.getMemory();
			Address min = null;
			Address max = null;

			if (!allBlocksInSameSpace()) {
				msg = "All memory block must be in the same address space.";
				return false;
			}

			for (MemoryBlock nextBlock : blocks) {
				if (min == null || nextBlock.getStart().compareTo(min) < 0) {
					min = nextBlock.getStart();
				}
				if (max == null || nextBlock.getEnd().compareTo(max) > 0) {
					max = nextBlock.getEnd();
				}
			}

			if (max == null) {
				return false;
			}

			long size = max.subtract(min) + 1;
			if (size <= 0 || size > Integer.MAX_VALUE) {
				msg = "Resulting Memory Block would be too large.";
				return false;
			}

			try {

				// start with first block
				MemoryBlock bigBlock = blocks.get(0);

				// for each block after
				for (int i = 1; i < blocks.size(); i++) {
					//   get block after
					MemoryBlock nextBlock = blocks.get(i);

					//   create new block for gap in between first block
					Address start = bigBlock.getEnd();
					start = start.addNoWrap(1);
					long length = nextBlock.getStart().subtract(start);
					if (length != 0) {
						MemoryBlock newBlock;
						if (bigBlock.isInitialized()) {
							newBlock = mem.createInitializedBlock(bigBlock.getName(), start, length,
								(byte) 0, null, false);
							newBlock.setRead(bigBlock.isRead());
							newBlock.setWrite(bigBlock.isWrite());
							newBlock.setExecute(bigBlock.isExecute());
							newBlock.setVolatile(bigBlock.isVolatile());
							newBlock.setSourceName("Resized Memory Block");
						}
						else {
							newBlock = mem.createUninitializedBlock(bigBlock.getName(), start,
								(int) length, false);
						}
						newBlock.setComment(bigBlock.getComment());
						//   join block with gap block
						bigBlock = mem.join(bigBlock, newBlock);
					}

					//  Rename the fragment based on the first block
					renameFragment(start, bigBlock.getName());

					//   join block with block after
					bigBlock = mem.join(bigBlock, nextBlock);
				}
				return true;

			}
			catch (RollbackException e) {
				throw e;
			}
			catch (Exception e) {
				msg = e.getMessage();
				if (msg == null) {
					msg = "Error merging blocks: " + e;
				}
			}
			catch (OutOfMemoryError e) {
				msg = "Not enough memory to merge blocks";
			}
			throw new RollbackException(msg);
		}

		private boolean allBlocksInSameSpace() {
			AddressSpace lastSpace = null;
			for (MemoryBlock block : blocks) {
				Address start = block.getStart();
				AddressSpace space = start.getAddressSpace();
				if (lastSpace != null && !lastSpace.equals(space)) {
					return false;
				}
				lastSpace = space;
			}
			return true;
		}

		@Override
		public String getName() {
			return "Merge Memory Blocks";
		}

		@Override
		public String getStatusMsg() {
			return msg;
		}
	}
}
