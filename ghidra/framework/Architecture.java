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

public enum Architecture {
	X86("x86", "i386"),
	X86_64("x86_64", "amd64"),
	POWERPC("ppc"),
	POWERPC_64("ppc64"),
	UNKNOWN("Unknown Architecture");

	/**
	 * Do not access this property directly. Access using Platform class.
	 */
	static final Architecture CURRENT_ARCHITECTURE = findCurrentArchitecture();

	private String[] supportedArchitectureNames;
	private String architectureName = System.getProperty("os.arch");

	private Architecture(String ... architectures) {
		supportedArchitectureNames = architectures;
	}
	
	private static Architecture findCurrentArchitecture() {
		String architectureNameProperty = System.getProperty("os.arch");
		for (Architecture architecture : values()) {			
			if ( architecture.supportsArchitecture(architectureNameProperty) ) {
				return architecture;
			}
		}
		return UNKNOWN;
	}

	private boolean supportsArchitecture( String architecture ) {
		for (String string : supportedArchitectureNames) {
			if ( string.equalsIgnoreCase( architecture ) ) {
				return true;
			}
		}
		return false;
	}
	
	@Override
	public String toString() {
		return name()+"("+architectureName+")";
	}
}
