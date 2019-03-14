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
package ghidra.framework;

public enum OperatingSystem {
	WINDOWS("Windows"),
	LINUX("Linux"),
	MAC_OS_X("Mac OS X"),
	UNSUPPORTED("Unsupported Operating System");

	/**
	 * Do not access this property directly. Access using Platform class.
	 */
	public static final OperatingSystem CURRENT_OPERATING_SYSTEM = findCurrentOperatingSystem();

	private String operatingSystemName;
	private String operatingSystemProperty = System.getProperty("os.name");
	
	private OperatingSystem(String operatingSystemName) {
		this.operatingSystemName = operatingSystemName;
	}

	private static OperatingSystem findCurrentOperatingSystem() {
		String operatingSystemNameProperty = System.getProperty("os.name");
		for (OperatingSystem operatingSystem : values()) {
			if (operatingSystemNameProperty.toLowerCase().indexOf(
					operatingSystem.operatingSystemName.toLowerCase()) > -1) {
				return operatingSystem;
			}
		}
		return UNSUPPORTED;
	}

	@Override
	public String toString() {
		return name()+"("+operatingSystemProperty+")";
	}
}
