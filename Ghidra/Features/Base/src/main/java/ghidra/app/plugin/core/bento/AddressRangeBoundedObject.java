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
package ghidra.app.plugin.core.bento;

import ghidra.program.model.address.AddressRange;

public class AddressRangeBoundedObject extends BoundedObject {

	public AddressRangeBoundedObject(AddressRange range) {
		super(range.getMinAddress().getOffset(), range.getMaxAddress().getOffset());
		this.loRep = range.getMinAddress();
		this.hiRep = range.getMaxAddress();
		this.obj = range;
	}

	@Override
	public BentoRadix getDefaultRadix() {
		return BentoRadix.HEX_LOWER;
	}

	@Override
	public Object getLowRep() {
		return loRep;
	}

	@Override
	public Object getHiRep() {
		return hiRep;
	}
}
