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
package mdemangler.datatype.extended;

import mdemangler.MDMang;
import mdemangler.datatype.MDDataType;

/**
 * This class represents the base class of a number of "extended" data types
 * within a Microsoft mangled symbol.
 */
public class MDExtendedType extends MDDataType {

	public MDExtendedType(MDMang dmang) {
		super(dmang, 2);
	}

	public MDExtendedType(MDMang dmang, int startIndexOffset) {
		super(dmang, startIndexOffset);
	}

	@Override
	public String getTypeName() {
		return "_UKNOWNEXTENDEDDATATYPE_";
	}
}
