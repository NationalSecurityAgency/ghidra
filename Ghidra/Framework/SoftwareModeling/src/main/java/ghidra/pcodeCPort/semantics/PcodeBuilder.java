/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcodeCPort.semantics;

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.translate.UnimplError;

// SLEIGH specific pcode generator
public abstract class PcodeBuilder {

	private int labelbase;
	private int labelcount;

	protected ParserWalker walker;

	protected abstract void dump(OpTpl op);

	public PcodeBuilder(int lbcnt) {
		labelbase = labelcount = lbcnt;
	}

	public void dispose() {
	}

	public int getLabelBase() {
		return labelbase;
	}

	public ParserWalker getCurrentWalker() {
		return walker;
	}

	public abstract void appendBuild(OpTpl bld, int secnum);

	public abstract void appendCrossBuild(OpTpl bld, int secnum);

	public abstract void delaySlot(OpTpl op);

	public abstract void setLabel(OpTpl op);

	public void build(ConstructTpl construct, int secnum) {
		if (construct == null) {
			throw new UnimplError("", 0); // Pcode is not implemented for this constructor
		}

		int oldbase = labelbase; // Recursively store old labelbase
		labelbase = labelcount; // Set the newbase
		labelcount += construct.numLabels(); // Add labels from this template

		VectorSTL<OpTpl> ops = construct.getOpvec();
		IteratorSTL<OpTpl> iter;
		for (iter = ops.begin(); !iter.isEnd(); iter.increment()) {
			OpTpl op = iter.get();
			switch (op.getOpcode()) {
				case CPUI_MULTIEQUAL: // formerly BUILD
					appendBuild(op, secnum);
					break;
				case CPUI_INDIRECT: // formerly DELAY_SLOT
					delaySlot(op);
					break;
				case CPUI_PTRADD: // formerly LABELBUILD
					setLabel(op);
					break;
				case CPUI_PTRSUB: // formerly CROSSBUILD
					appendCrossBuild(op, secnum);
					break;
				default:
					dump(op);
					break;
			}
		}
		labelbase = oldbase; // Restore old labelbase
	}

}
