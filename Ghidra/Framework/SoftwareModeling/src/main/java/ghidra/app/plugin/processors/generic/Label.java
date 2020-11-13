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
package ghidra.app.plugin.processors.generic;

import ghidra.program.model.mem.MemBuffer;

/**
 * 
 *
 * To change this generated comment edit the template variable "typecomment":
 * {@literal Window>Preferences>Java>Templates.}
 * To enable and disable the creation of type comments go to
 * {@literal Window>Preferences>Java>Code Generation.}
 */
public class Label implements ExpressionValue {

	public Label() {}

	public long longValue(MemBuffer buf, int off) {
		return buf.getAddress().getOffset() + off;
	}

	public int length(MemBuffer buf, int off) {	return 0;}

}
