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
package mdemangler.object;

import mdemangler.MDException;
import mdemangler.MDMang;
import mdemangler.naming.MDFragmentName;

/**
 * This class represents a derivative of an <b><code>MDObject</code></b> which is a C object
 *  (vs. a C++ object).
 */
public class MDObjectC extends MDObject {
	protected MDFragmentName name;

	public MDObjectC(MDMang dmang) {
		super(dmang);
		name = new MDFragmentName(dmang);
	}

	@Override
	public void insert(StringBuilder builder) {
		builder.append(name);
	}

	@Override
	protected void parseInternal() throws MDException {
		name.parse();
	}
}

/******************************************************************************/
/******************************************************************************/
