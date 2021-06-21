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
package ghidra.app.plugin.core.function.tags;

import generic.json.Json;
import ghidra.program.model.listing.FunctionTag;

class FunctionTagRowObject {

	private FunctionTag tag;
	private int count;

	FunctionTagRowObject(FunctionTag tag, int count) {
		this.tag = tag;
		this.count = count;
	}

	FunctionTag getTag() {
		return tag;
	}

	String getName() {
		return tag.getName();
	}

	int getCount() {
		return count;
	}

	void setCount(int count) {
		this.count = count;
	}

	boolean isImmutable() {
		return tag instanceof InMemoryFunctionTag;
	}

	String getComment() {
		return tag.getComment();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "\n" + Json.toString(this);
	}
}
