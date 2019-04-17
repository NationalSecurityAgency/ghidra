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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

import ghidra.program.model.address.AddressFactory;

public class BlockMap {
	private AddressFactory factory;
	private ArrayList<PcodeBlock> sortlist;
	private ArrayList<PcodeBlock> leaflist;
	private ArrayList<GotoReference> gotoreflist;

	private static class GotoReference {
		public PcodeBlock gotoblock;
		public int rootindex;
		public int depth;

		public GotoReference(PcodeBlock gblock, int root, int d) {
			gotoblock = gblock;
			rootindex = root;
			depth = d;
		}
	}

	public BlockMap(AddressFactory fac) {
		factory = fac;
		leaflist = new ArrayList<PcodeBlock>();
		gotoreflist = new ArrayList<GotoReference>();
		sortlist = new ArrayList<PcodeBlock>();
	}

	public BlockMap(BlockMap op2) {
		factory = op2.factory;
		leaflist = op2.leaflist;
		gotoreflist = op2.gotoreflist;
		sortlist = new ArrayList<PcodeBlock>();
	}

	public AddressFactory getAddressFactory() {
		return factory;
	}

	private static void sortList(ArrayList<PcodeBlock> list) {
		Comparator<PcodeBlock> comp = new Comparator<PcodeBlock>() {

			@Override
			public int compare(PcodeBlock o1, PcodeBlock o2) {
				return o1.index - o2.index;
			}
		};
		Collections.sort(list, comp);
	}

	private static PcodeBlock resolveBlock(int btype) {
		switch (btype) {
			case PcodeBlock.BASIC:
				return new PcodeBlockBasic();
			case PcodeBlock.CONDITION:
				return new BlockCondition();
			case PcodeBlock.COPY:
				return new BlockCopy();
			case PcodeBlock.DOWHILE:
				return new BlockDoWhile();
			case PcodeBlock.GOTO:
				return new BlockGoto();
			case PcodeBlock.GRAPH:
				return new BlockGraph();
			case PcodeBlock.IFELSE:
				return new BlockIfElse();
			case PcodeBlock.IFGOTO:
				return new BlockIfGoto();
			case PcodeBlock.INFLOOP:
				return new BlockInfLoop();
			case PcodeBlock.LIST:
				return new BlockList();
			case PcodeBlock.MULTIGOTO:
				return new BlockMultiGoto();
			case PcodeBlock.PLAIN:
				return new PcodeBlock();
			case PcodeBlock.PROPERIF:
				return new BlockProperIf();
			case PcodeBlock.SWITCH:
				return new BlockSwitch();
			case PcodeBlock.WHILEDO:
				return new BlockWhileDo();
		}
		return null;
	}

	/**
	 * Assume blocks are in index order, find the block with index -ind-
	 * @param ind is the block index to match
	 * @return the matching PcodeBlock
	 */
	public PcodeBlock findLevelBlock(int ind) {
		return findBlock(sortlist, ind);
	}

	public void sortLevelList() {
		sortList(sortlist);
	}

	private static PcodeBlock findBlock(ArrayList<PcodeBlock> list, int ind) {
		int min = 0;
		int max = list.size() - 1;
		while (min <= max) {
			int mid = (min + max) / 2;
			PcodeBlock block = list.get(mid);
			if (block.getIndex() == ind) {
				return block;
			}
			if (block.getIndex() < ind) {
				min = mid + 1;
			}
			else {
				max = mid - 1;
			}
		}
		return null;
	}

	public PcodeBlock createBlock(String name, int index) {
		int btype = PcodeBlock.nameToType(name);
		PcodeBlock res = resolveBlock(btype);
		res.setIndex(index);
		sortlist.add(res);
		if ((btype == PcodeBlock.PLAIN) || (btype == PcodeBlock.COPY) ||
			(btype == PcodeBlock.BASIC)) {
			leaflist.add(res);
		}
		return res;
	}

	public void addGotoRef(PcodeBlock gblock, int root, int depth) {
		GotoReference ref = new GotoReference(gblock, root, depth);
		gotoreflist.add(ref);
	}

	public void resolveGotoReferences() {
		sortList(leaflist);
		for (int i = 0; i < gotoreflist.size(); ++i) {
			GotoReference gotoref = gotoreflist.get(i);
			PcodeBlock bl = findBlock(leaflist, gotoref.rootindex);
			int depth = gotoref.depth;
			while (depth > 0) {
				depth -= 1;
				bl = bl.getParent();
			}
			if (gotoref.gotoblock instanceof BlockGoto) {
				BlockGoto gotoblock = (BlockGoto) gotoref.gotoblock;
				gotoblock.setGotoTarget(bl);
			}
			else if (gotoref.gotoblock instanceof BlockIfGoto) {
				BlockIfGoto gotoblock = (BlockIfGoto) gotoref.gotoblock;
				gotoblock.setGotoTarget(bl);
			}
			else if (gotoref.gotoblock instanceof BlockMultiGoto) {
				BlockMultiGoto gotoblock = (BlockMultiGoto) gotoref.gotoblock;
				gotoblock.addBlock(bl);
			}
		}
	}
}
