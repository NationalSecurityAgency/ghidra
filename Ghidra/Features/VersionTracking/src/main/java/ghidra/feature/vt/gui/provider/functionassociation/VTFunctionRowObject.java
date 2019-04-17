/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.provider.functionassociation;

class VTFunctionRowObject implements Comparable<VTFunctionRowObject> {

	private final FunctionAssociationInfo info;

	VTFunctionRowObject(FunctionAssociationInfo info) {
		this.info = info;
	}

	FunctionAssociationInfo getInfo() {
		return info;
	}

	@Override
	public int hashCode() {
		return info.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		VTFunctionRowObject other = (VTFunctionRowObject) obj;
		return info.equals(other.info);
	}

	@Override
	public int compareTo(VTFunctionRowObject o) {
		return info.compareTo(o.info);
	}

}
