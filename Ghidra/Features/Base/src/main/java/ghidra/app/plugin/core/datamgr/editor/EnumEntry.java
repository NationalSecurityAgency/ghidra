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
package ghidra.app.plugin.core.datamgr.editor;

import generic.json.Json;

public class EnumEntry {
	private String name;
	private long value;
	private String comment;

	public EnumEntry(String name, long value, String comment) {
		this.name = name;
		this.value = value;
		this.comment = comment;
	}

	public String getName() {
		return name;
	}

	public long getValue() {
		return value;
	}

	public String getComment() {
		return comment;
	}

	public void setName(String newName) {
		this.name = newName;
	}

	public void setValue(Long newValue) {
		this.value = newValue;
	}

	public void setComment(String newComment) {
		this.comment = newComment;
	}

	@Override
	public String toString() {
		return Json.toString(this);
	}
}
