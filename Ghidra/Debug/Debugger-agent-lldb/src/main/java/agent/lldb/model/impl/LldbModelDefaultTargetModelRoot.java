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
package agent.lldb.model.impl;

import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.schema.TargetObjectSchema;

public class LldbModelDefaultTargetModelRoot extends LldbModelTargetObjectImpl
		implements TargetAggregate {

	public LldbModelDefaultTargetModelRoot(LldbModelImpl model, String typeHint) {
		super(model, null, null, null, typeHint);
	}

	public LldbModelDefaultTargetModelRoot(LldbModelImpl model, String typeHint,
			TargetObjectSchema schema) {
		super(model, null, null, null, typeHint, schema);
	}

}
