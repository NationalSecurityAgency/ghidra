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
package ghidra.feature.fid.service;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;

public class Location {
	private final DomainFile domainFile;
	private final String functionName;
	private final Address entryPoint;

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((domainFile == null) ? 0 : domainFile.getFileID().hashCode());
		result = prime * result + ((entryPoint == null) ? 0 : entryPoint.hashCode());
		result = prime * result + ((functionName == null) ? 0 : functionName.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Location other = (Location) obj;
		if (domainFile == null) {
			if (other.domainFile != null) {
				return false;
			}
		}
		else if (!domainFile.getFileID().equals(other.domainFile.getFileID())) {
			return false;
		}
		if (entryPoint == null) {
			if (other.entryPoint != null) {
				return false;
			}
		}
		else if (!entryPoint.equals(other.entryPoint)) {
			return false;
		}
		if (functionName == null) {
			if (other.functionName != null) {
				return false;
			}
		}
		else if (!functionName.equals(other.functionName)) {
			return false;
		}
		return true;
	}

	public Location(DomainFile domainFile, String functionName, Address entryPoint) {
		this.domainFile = domainFile;
		this.functionName = functionName;
		this.entryPoint = entryPoint;
	}

	public DomainFile getDomainFile() {
		return domainFile;
	}

	public String getFunctionName() {
		return functionName;
	}

	public Address getFunctionEntryPoint() {
		return entryPoint;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		if (domainFile != null) {
			sb.append(domainFile.getPathname());
			sb.append(":");
		}
		sb.append(functionName);
		if (entryPoint != null) {
			sb.append(" (");
			sb.append(entryPoint.toString());
			sb.append(")");
		}
		return sb.toString();
	}
}
