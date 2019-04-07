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
 * This class represents a Microsoft C++ RTTI0 internal C++ structure.
 *  It is not doing any additional work at this time, but this separate
 *  object is being created for future extension.
 */
public class MDRTTI0 extends AbstractMDMetaClass {

	public MDRTTI0(MDMang dmang) {
		super(dmang);
	}
}

/******************************************************************************/
/******************************************************************************/
