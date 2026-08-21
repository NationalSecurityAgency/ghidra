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
package ghidra.pcode.exec;

/**
 * A p-code executor state formed from a piece whose address and value types are the same
 *
 * @param <T> the type of values and addresses in the state
 */
public class DefaultPcodeExecutorState<T> extends AbstractPcodeExecutorState<T, T> {
	protected final PcodeArithmetic<T> arithmetic;

	public DefaultPcodeExecutorState(PcodeExecutorStatePiece<T, T> piece) {
		super(piece);
		this.arithmetic = piece.getArithmetic();
	}

	@Override
	protected T extractAddress(T value) {
		return value;
	}

	@Override
	public PcodeExecutorState<T> fork(PcodeStateCallbacks cb) {
		return new DefaultPcodeExecutorState<>(piece.fork(cb));
	}
}
