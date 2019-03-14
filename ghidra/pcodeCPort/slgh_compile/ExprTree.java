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
package ghidra.pcodeCPort.slgh_compile;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.pcodeCPort.semantics.*;
import ghidra.sleigh.grammar.Location;

//A flattened expression tree
public class ExprTree {
	public final Location location;

	VectorSTL<OpTpl> ops; // flattened ops making up the expression
	VarnodeTpl outvn; // Output varnode of the expression

	// If the last op has an output, -outvn- is
	// a COPY of that varnode
	public ExprTree(Location location) {
		this.location = location;
		ops = null;
		outvn = null;
	}

	public ExprTree(Location location, VarnodeTpl vn) {
		this.location = location;
		outvn = vn;
		ops = new VectorSTL<OpTpl>();
	}

	public ExprTree(Location location, OpTpl op) {
		this.location = location;
		ops = new VectorSTL<OpTpl>();
		ops.push_back(op);
		if (op.getOut() != null)
			outvn = new VarnodeTpl(location, op.getOut());
		else
			outvn = null;
	}

	// Force the output of the expression to be new out
	// If the original output is named, this requires
	// an extra COPY op
	public void setOutput(Location newLocation, VarnodeTpl newout) {
		OpTpl op;
		if (outvn == null)
			throw new SleighError("Expression has no output", newLocation);
		if (outvn.isUnnamed()) {
			op = ops.back();
			op.clearOutput();
			op.setOutput(newout);
		}
		else {
			op = new OpTpl(newLocation, OpCode.CPUI_COPY);
			op.addInput(outvn);
			op.setOutput(newout);
			ops.push_back(op);
		}
		outvn = new VarnodeTpl(newLocation, newout);
	}

	ConstTpl getSize() {
		return outvn.getSize();
	}

	// Create op expression with entire list of expression
	// inputs
	static VectorSTL<OpTpl> appendParams(OpTpl op, VectorSTL<ExprTree> param) {
		VectorSTL<OpTpl> res = new VectorSTL<OpTpl>();

		for (int i = 0; i < param.size(); ++i) {
			res.appendAll(param.get(i).ops);
			param.get(i).ops.clear();
			op.addInput(param.get(i).outvn);
			param.get(i).outvn = null;
		}
		res.push_back(op);
		return res;
	}

	// Grab the op vector and delete the output expression
	public static VectorSTL<OpTpl> toVector(ExprTree expr) {
		VectorSTL<OpTpl> res = expr.ops;
		expr.ops = null;
		return res;
	}
}
