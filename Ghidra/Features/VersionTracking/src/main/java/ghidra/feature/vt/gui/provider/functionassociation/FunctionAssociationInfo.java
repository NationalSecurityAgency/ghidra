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

public class FunctionAssociationInfo implements Comparable<FunctionAssociationInfo> {
	private long functionID;
	private boolean isInAssociation;
	private boolean isInAcceptedAssociation;
	private boolean isFilterInfoInitialized;

	public FunctionAssociationInfo(long key) {
		this.functionID = key;
	}

	public boolean isInAssociation() {
		return isInAssociation;
	}

	public boolean isInAcceptedAssociation() {
		return isInAcceptedAssociation;
	}

	public void setFilterData(boolean isInAssociation, boolean isInAcceptedAssociation) {
		this.isInAssociation = Boolean.valueOf(isInAssociation);
		this.isInAcceptedAssociation = Boolean.valueOf(isInAcceptedAssociation);
		this.isFilterInfoInitialized = true;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != this.getClass()) {
			return false;
		}
		FunctionAssociationInfo other = (FunctionAssociationInfo) obj;
		return functionID == other.functionID;
	}

	@Override
	public int hashCode() {
		return (int) functionID;
	}

	public long getFunctionID() {
		return functionID;
	}

	public boolean isFilterInitialized() {
		return isFilterInfoInitialized;
	}

	@Override
	public int compareTo(FunctionAssociationInfo o) {
		if (functionID == o.functionID) {
			return 0;
		}
		return functionID > o.functionID ? 1 : -1;
	}
}
