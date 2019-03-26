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
package ghidra.base.widgets.table.constraint.provider;

import docking.widgets.table.constraint.ColumnTypeMapper;
import ghidra.program.model.symbol.Namespace;

/**
 * Converts Namespace Column objects to Strings so that column gets String type column
 * filters
 */
public class NamespaceColumnTypeMapper extends ColumnTypeMapper<Namespace, String> {

	@Override
	public String convert(Namespace namespace) {
		return namespace.getName();
	}

}
