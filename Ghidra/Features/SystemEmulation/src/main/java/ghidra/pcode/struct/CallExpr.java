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
package ghidra.pcode.struct;

import java.util.List;
import java.util.stream.Collectors;

import ghidra.pcode.struct.StructuredSleigh.RVal;
import ghidra.pcode.struct.StructuredSleigh.UseropDecl;
import ghidra.program.model.data.DataType;

/**
 * A p-code userop invocation expression
 * 
 * <p>
 * Userops are essentially treated as functions. They can be invoked passing a list of parameters,
 * and the expression takes the value it returns (via {@link StructuredSleigh#_result(RVal)}.
 */
public class CallExpr extends Expr {
	private final UseropDecl userop;
	private final List<RValInternal> args;

	private CallExpr(StructuredSleigh ctx, DataType type, UseropDecl userop,
			List<RValInternal> args) {
		super(ctx, type);
		this.userop = userop;
		this.args = args;
	}

	/**
	 * Build a call expression
	 * 
	 * @param ctx the context
	 * @param userop the userop to invoke
	 * @param args the arguments to pass in (by reference)
	 */
	protected CallExpr(StructuredSleigh ctx, UseropDecl userop, List<RVal> args) {
		this(ctx, userop.getReturnType(), userop,
			args.stream().map(a -> (RValInternal) a).collect(Collectors.toList()));
	}

	@Override
	public RVal cast(DataType type) {
		return new CallExpr(ctx, type, userop, args);
	}

	@Override
	public String toString() {
		return "<Call " + userop.getName() + "(" +
			args.stream().map(a -> a.toString()).collect(Collectors.joining(",")) + ")>";
	}

	@Override
	public StringTree generate(RValInternal parent) {
		StringTree st = new StringTree();
		st.append(userop.getName());
		st.append("(");
		boolean first = false;
		for (RValInternal a : args) {
			if (!first) {
				first = true;
			}
			else {
				st.append(",");
			}
			st.append(a.generate(this));
		}
		st.append(")");
		return st;
	}
}
