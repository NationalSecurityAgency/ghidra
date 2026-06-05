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
package ghidra.pcode.emu.jit.var;

/**
 * An abstract implementation of {@link JitVar}.
 */
public abstract class AbstractJitVar extends AbstractJitVal implements JitVar {
	protected final int id;

	/**
	 * Construct a variable with the given id and size.
	 * 
	 * @param id a unique id among all variables in the same use-def graph
	 * @param size the size in bytes
	 */
	public AbstractJitVar(int id, int size) {
		super(size);
		this.id = id;
	}

	@Override
	public int id() {
		return id;
	}

	@Override
	public String toString() {
		return "%s[id=%d]".formatted(getClass().getSimpleName(), id);
	}
}
