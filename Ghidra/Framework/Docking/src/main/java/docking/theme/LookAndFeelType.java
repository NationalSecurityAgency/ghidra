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
package docking.theme;

import com.formdev.flatlaf.*;

import docking.theme.laf.*;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;

public enum LookAndFeelType {
	METAL("Metal", new MetalLookAndFeelInstaller()),
	NIMBUS("Nimbus", new NimbusLookAndFeelInstaller()),
	GTK("GTK+", new GTKLookAndFeelInstaller()),
	MOTIF("CDE/Motif", new MotifLookAndFeelInstaller()),
	FLAT_LIGHT("Flat Light", new FlatLookAndFeelInstaller(new FlatLightLaf())),
	FLAT_DARK("Flat Dark", new FlatLookAndFeelInstaller(new FlatDarkLaf())),
	FLAT_DARCULA("Flat Light", new FlatLookAndFeelInstaller(new FlatDarculaLaf())),
	WINDOWS("Windows", new WindowsLookAndFeelInstaller()),
	WINDOWS_CLASSIC("Windows Classic", new WindowsClassicLookAndFeelInstaller()),
	MAC("Mac OS X", new MacLookAndFeelInstaller()),
	SYSTEM("System", getSystemLookAndFeelInstaller());

	private String name;
	private LookAndFeelInstaller installer;

	private LookAndFeelType(String name, LookAndFeelInstaller installer) {
		this.name = name;
		this.installer = installer;
	}

	public String getName() {
		return name;
	}

	public static LookAndFeelType fromName(String name) {
		for (LookAndFeelType type : values()) {
			if (type.getName().equals(name)) {
				return type;
			}
		}
		return null;
	}

	private static LookAndFeelInstaller getSystemLookAndFeelInstaller() {
		OperatingSystem OS = Platform.CURRENT_PLATFORM.getOperatingSystem();
		if (OS == OperatingSystem.LINUX) {
			return NIMBUS.installer;
		}
		else if (OS == OperatingSystem.MAC_OS_X) {
			return MAC.installer;
		}
		else if (OS == OperatingSystem.WINDOWS) {
			return WINDOWS.installer;
		}
		return NIMBUS.installer;
	}

	public boolean isSupported() {
		return installer.isSupportedForCurrentPlatform();
	}

	public void install() throws Exception {
		installer.install();
	}

}
