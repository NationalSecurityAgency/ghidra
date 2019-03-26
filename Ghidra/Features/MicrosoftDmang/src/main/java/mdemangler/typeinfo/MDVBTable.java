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
package mdemangler.typeinfo;

import mdemangler.MDMang;

/**
 * This class represents a C++ Virtual Base Table.
 * This class is not the only class to extend MDVxTable.  Neither class does
 * any additional work at this time, but the represent different constructs
 * within C++ implementations and could do additional work in the future, so
 * this current do-nothing class should not be refactored out.
 */
public class MDVBTable extends MDVxTable {

	public MDVBTable(MDMang dmang) {
		super(dmang);
	}
}

/******************************************************************************/
/******************************************************************************/
