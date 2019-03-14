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
package ghidra.app.plugin.processors.sleigh;

import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.program.model.pcode.PcodeOp;

/**
 * Class for walking pcode templates OpTpl in the correct order
 * Supports walking the tree of an entire SleighInstructionPrototype or just a single ConstructTpl
 *
 */
public class OpTplWalker {
	
	private ConstructState point;		// The current node being visited
	private OpTpl[] oparray;			// current array of ops being traversed
	private int depth;					// Depth of current node within the tree
	private int breadcrumb[];			// Path of operands from the root
	private int maxsize;				// Maximum number of directives for this point
	private int sectionnum;

	private void setupPoint() {
		maxsize = 0;
		oparray = null;
		Constructor ct = point.getConstructor();
		if (ct == null)
			return;
		ConstructTpl tpl;
		if (sectionnum < 0) {
			tpl = ct.getTempl();
			if (tpl == null)
				return;
		}
		else 
			tpl = ct.getNamedTempl(sectionnum);
		if (tpl == null) {			// Empty named section implies straight list of build directives
			maxsize = ct.getNumOperands();
		}
		else {
			oparray = tpl.getOpVec();
			maxsize = oparray.length;
		}		
		
	}
	
	/**
	 * Constructor for walking an entire parse tree
	 * @param root is the root ConstructState of the tree
	 * @param sectionnum is the named section to traverse (or -1 for main section)
	 */
	public OpTplWalker(ConstructState root,int sectionnum) {
		this.sectionnum = sectionnum;
		point = root;
		// NOTE: breadcrumb array size limits depth of parse
		breadcrumb = new int[64];
		depth = 0;
		breadcrumb[0] = 0;
		setupPoint();
	}
	
	/**
	 * Constructor for walking a single template
	 * @param tpl
	 */
	public OpTplWalker(ConstructTpl tpl) {
		point = null;
		breadcrumb = new int[1];
		depth = 0;
		breadcrumb[0] = 0;
		oparray = tpl.getOpVec();
		maxsize = oparray.length;
	}
	
	public ConstructState getState() {
		return point;
	}
	
	public boolean isState() {
		if (point != null)
			return true;
		return (maxsize > 0);
	}
	
	/**
	 * While walking the OpTpl's in order, follow a particular BUILD directive into its respective Constructor and ContructTpl
	 * Use popBuild to backtrack
	 * @param buildnum is the operand number of the BUILD directive to follow
	 */
	public void pushBuild(int buildnum) {
		point = point.getSubState(buildnum);
		depth += 1;
		breadcrumb[depth] = 0;
		setupPoint();
	}
	
	/**
	 * Move to the parent of the current node
	 */
	public void popBuild() {
		if (point == null) {
			maxsize = 0;
			oparray = null;
			return;
		}
		point = point.getParent();
		depth -= 1;
		if (point != null)
			setupPoint();
		else {
			maxsize = 0;
			oparray = null;
		}
	}
	
	public Object nextOpTpl() {
		int curind = breadcrumb[depth]++;
		if (curind >= maxsize)
			return null;
		if (oparray == null)
			return new Integer(curind);				// Virtual build directive
		OpTpl op = oparray[curind];
		if (op.getOpcode() != PcodeOp.MULTIEQUAL)	// if NOT a build directive
			return op;								// return ordinary OpTpl
		curind = (int)op.getInput()[0].getOffset().getReal();		// Get the operand index from the build directive
		return new Integer(curind);
	}

}
