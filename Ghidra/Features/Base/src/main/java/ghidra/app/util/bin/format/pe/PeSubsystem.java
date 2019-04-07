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
package ghidra.app.util.bin.format.pe;

public enum PeSubsystem {

	// @formatter:off
	 IMAGE_SUBSYSTEM_UNKNOWN("IMAGE_SUBSYSTEM_UNKNOWN", 0, 
		 "An unknown subsystem"),
	 IMAGE_SUBSYSTEM_NATIVE("IMAGE_SUBSYSTEM_NATIVE", 1, 
		 "Device drivers and native Windows processes"),
	 IMAGE_SUBSYSTEM_WINDOWS_GUI("IMAGE_SUBSYSTEM_WINDOWS_GUI", 2, 
		 "The Windows graphical user interface (GUI) subsystem"),
	 IMAGE_SUBSYSTEM_WINDOWS_CUI("IMAGE_SUBSYSTEM_WINDOWS_CUI", 3, 
		 "The Windows character subsystem"),
	 IMAGE_SUBSYSTEM_OS2_CUI("IMAGE_SUBSYSTEM_OS2_CUI", 5, 
		 "The OS/2 character subsystem"),
	 IMAGE_SUBSYSTEM_POSIX_CUI("IMAGE_SUBSYSTEM_POSIX_CUI", 7, 
		 "The Posix character subsystem"),
	 IMAGE_SUBSYSTEM_NATIVE_WINDOWS("IMAGE_SUBSYSTEM_NATIVE_WINDOWS", 8, 
		 "Native Win9x driver"),
	 IMAGE_SUBSYSTEM_WINDOWS_CE_GUI("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", 9, 
		 "Windows CE"),
	 IMAGE_SUBSYSTEM_EFI_APPLICATION("IMAGE_SUBSYSTEM_EFI_APPLICATION", 10, 
		 "An Extensible Firmware Interface (EFI) application"),
	 IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", 11, 
		 "An Extensible Firmware Interface (EFI) driver with boot services"),
	 IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", 12, 
		 "An Extensible Firmware Interface (EFI) driver with run-time services"),
	 IMAGE_SUBSYSTEM_EFI_ROM("IMAGE_SUBSYSTEM_EFI_ROM", 13, 
		 "An Extensible Firmware Interface (EFI) ROM image"),
	 IMAGE_SUBSYSTEM_XBOX("IMAGE_SUBSYSTEM_XBOX", 14, 
		 "XBOX Image"),
	 IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", 16, 
		 "Windows boot application.");
	// @formatter:on

	private final String alias;
	private final int value;
	private final String description;

	private PeSubsystem(String alias, int value, String description) {
		this.alias = alias;
		this.value = value;
		this.description = description;
	}

	public String getAlias() {
		return alias;
	}

	public int getValue() {
		return value;
	}

	public String getDescription() {
		return description;
	}

	public static PeSubsystem parse(int id) {
		for (PeSubsystem ss : values()) {
			if (ss.getValue() == id) {
				return ss;
			}
		}
		throw new IllegalArgumentException("Can't resolve '" + id + "' to known PeSubsystem");
	}

}
