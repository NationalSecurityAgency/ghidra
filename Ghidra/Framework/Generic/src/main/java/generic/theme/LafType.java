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
package generic.theme;

import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;

import generic.theme.laf.*;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.exception.AssertException;

public enum LafType {
	METAL("Metal"),
	NIMBUS("Nimbus"),
	GTK("GTK+"),
	MOTIF("CDE/Motif"),
	FLAT_LIGHT("Flat Light"),
	FLAT_DARK("Flat Dark"),
	FLAT_DARCULA("Flat Darcula"),
	WINDOWS("Windows"),
	WINDOWS_CLASSIC("Windows Classic"),
	MAC("Mac OS X");

	private String name;

	private LafType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public static LafType fromName(String name) {
		for (LafType type : values()) {
			if (type.getName().equals(name)) {
				return type;
			}
		}
		return null;
	}

	public boolean isSupported() {
		LookAndFeelInfo[] installedLookAndFeels = UIManager.getInstalledLookAndFeels();
		for (LookAndFeelInfo info : installedLookAndFeels) {
			if (name.equals(info.getName())) {
				return true;
			}
		}
		return false;
	}

	public LookAndFeelManager getLookAndFeelManager() {
		return getManager(this);
	}

	private static LookAndFeelManager getManager(LafType lookAndFeel) {
		switch (lookAndFeel) {
			case MAC:
			case METAL:
			case WINDOWS:
			case WINDOWS_CLASSIC:
				return new GenericLookAndFeelManager(lookAndFeel);
			case FLAT_DARCULA:
			case FLAT_DARK:
			case FLAT_LIGHT:
				return new GenericFlatLookAndFeelManager(lookAndFeel);
			case GTK:
				return new GtkLookAndFeelManager();
			case MOTIF:
				return new MotifLookAndFeelManager();
			case NIMBUS:
				return new NimbusLookAndFeelManager();
			default:
				throw new AssertException("No lookAndFeelManager defined for " + lookAndFeel);
		}
	}

	public static LafType getDefaultLookAndFeel() {
		OperatingSystem OS = Platform.CURRENT_PLATFORM.getOperatingSystem();
		switch (OS) {
			case MAC_OS_X:
				return MAC;
			case WINDOWS:
				return WINDOWS;
			case LINUX:
			case UNSUPPORTED:
			default:
				return NIMBUS;
		}
	}
}
