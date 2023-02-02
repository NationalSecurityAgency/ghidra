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
package ghidra.pcode.eval;

import ghidra.pcode.exec.PcodeExecutor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * An evaluator of high varnodes
 * 
 * <p>
 * This is a limited analog to {@link PcodeExecutor} but for high p-code. It is limited in that it
 * can only "execute" parts of the AST that represent expressions, as a means of evaluating them. If
 * it encounters, e.g., a {@link PcodeOp#MULTIEQUAL} or phi node, it will terminate throw an
 * exception.
 * 
 * @param <T> the type of values resulting from evaluation
 */
public interface VarnodeEvaluator<T> {
	/**
	 * Evaluate a varnode
	 * 
	 * @param program the program containing the varnode
	 * @param vn the varnode to evaluate
	 * @return the value of the varnode
	 */
	T evaluateVarnode(Program program, Varnode vn);

	/**
	 * Evaluate variable storage
	 * 
	 * <p>
	 * Each varnode is evaluated as in {@link #evaluateStorage(VariableStorage)} and then
	 * concatenated. The lower-indexed varnodes in storage are the more significant pieces, similar
	 * to big endian.
	 * 
	 * @param program the program containing the variable storage
	 * @param storage the storage
	 * @return the value of the storage
	 */
	T evaluateStorage(Program program, VariableStorage storage);

	/**
	 * Evaluate a high p-code op
	 * 
	 * @param program the program containing the op
	 * @param op the p-code op
	 * @return the value of the op's output
	 */
	T evaluateOp(Program program, PcodeOp op);
}
