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

import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;

import generic.theme.laf.*;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.exception.AssertException;

/**
 * An enumeration that represents the set of supported {@link LookAndFeel}s
 */
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

	/**
	 * Returns the name of this LafType.
	 * @return the name of this LafType.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the LafType for the given name or null if the given name does not match any types
	 * @param name the name to search a LafType for.
	 * @return the LafType for the given name or null if the given name does not match any types
	 */
	public static LafType fromName(String name) {
		for (LafType type : values()) {
			if (type.getName().equals(name)) {
				return type;
			}
		}
		return null;
	}

	/**
	 * Returns true if the {@link LookAndFeel} represented by this LafType is supported on the
	 * current platform.
	 * @return true if the {@link LookAndFeel} represented by this LafType is supported on the
	 * current platform
	 */
	public boolean isSupported() {
		LookAndFeelInfo[] installedLookAndFeels = UIManager.getInstalledLookAndFeels();
		for (LookAndFeelInfo info : installedLookAndFeels) {
			if (name.equals(info.getName())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns a LookAndFeelManager that can install and update the {@link LookAndFeel} associated
	 * with this LafType.
	 * @return a LookAndFeelManager that can install and update the {@link LookAndFeel} associated
	 * with this LafType.
	 */
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

	/**
	 * Returns the default LafType for the current platform.
	 * @return the default LafType for the current platform.
	 */
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
