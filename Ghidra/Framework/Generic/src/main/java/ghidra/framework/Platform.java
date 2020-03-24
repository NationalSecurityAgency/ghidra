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
package ghidra.framework;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Identifies the current platform (operating system and architecture) and
 * identifies the appropriate module OS directory which contains native binaries
 */
public enum Platform {

	/**
	 * Identifies a Windows 32-bit OS (e.g., Windows NT, 2000, XP, etc.).
	 */
	WIN_32(OperatingSystem.WINDOWS, Architecture.X86, "win32", ".dll", ".exe"),

	/**
	 * Identifies a Windows 64-bit OS (e.g., XP-64, etc.).
	 */
	WIN_64(OperatingSystem.WINDOWS, Architecture.X86_64, "win64", ".dll", ".exe"),

	/**
	 * Identifies a Windows OS, the architecture for which we do not know or have not encountered
	 */
	WIN_UNKOWN(OperatingSystem.WINDOWS, Architecture.UNKNOWN, "win64", ".dll", ".exe"),

	/**
	 * Identifies a Linux OS.
	 */
	LINUX(OperatingSystem.LINUX, Architecture.X86, "linux32", ".so", ""),

	/**
	 * Identifies a Linux OS x86-64.
	 */
	LINUX_64(OperatingSystem.LINUX, Architecture.X86_64, "linux64", ".so", ""),

	/**
	 * Identifies a Linux OS, the architecture for which we do not know or have not encountered
	 */
	LINUX_UKNOWN(OperatingSystem.LINUX, Architecture.UNKNOWN, "linux64", ".so", ""),

	/**
	 * Identifies a Mac OS X for the Intel x86 32-bit platform.
	 */
	MAC_OSX_32(OperatingSystem.MAC_OS_X, Architecture.X86, "osx32", ".dylib", ""),

	/**
	 * Identifies a Mac OS X for the Intel x86 64-bit platform.
	 */
	MAC_OSX_64(OperatingSystem.MAC_OS_X, Architecture.X86_64, "osx64", ".dylib", ""),

	/**
	 * Identifies a Mac OS, the architecture for which we do not know or have not encountered
	 */
	MAC_UNKNOWN(OperatingSystem.MAC_OS_X, Architecture.UNKNOWN, "osx64", ".dylib", ""),

	/**
	 * Identifies an unsupported OS.
	 */
	UNSUPPORTED(OperatingSystem.UNSUPPORTED, Architecture.UNKNOWN, null, null, "");

	/**
	 * A constant identifying the current platform.
	 */
	public static final Platform CURRENT_PLATFORM = findCurrentPlatform();

	private OperatingSystem operatingSystem;
	private Architecture architecture;
	private String directoryName;
	private String libraryExtension;

	private final String executableExtension;

	private Platform(OperatingSystem operatingSystem, Architecture architecture,
			String directoryName, String libraryExtension, String executableExtension) {
		this.operatingSystem = operatingSystem;
		this.architecture = architecture;
		this.directoryName = directoryName;
		this.libraryExtension = libraryExtension;
		this.executableExtension = executableExtension;
	}

	/**
	 * Returns the operating system for this platform.
	 * @return the operating system for this platform
	 */
	public OperatingSystem getOperatingSystem() {
		return operatingSystem;
	}

	/**
	 * Returns the architecture for this platform.
	 * @return the architecture for this platform
	 */
	public Architecture getArchitecture() {
		return architecture;
	}

	/**
	 * Returns the directory name of the current platform.
	 * @return the directory name of the current platform
	 */
	public String getDirectoryName() {
		return directoryName;
	}

	/**
	 * Returns the library extension for this platform.
	 * @return the library extension for this platform
	 */
	public String getLibraryExtension() {
		return libraryExtension;
	}

	/**
	 * Based on the current platform, 
	 * returns an operating system specific
	 * library paths that are not found on the
	 * PATH environment variable.
	 * @return additional library paths
	 */
	public List<String> getAdditionalLibraryPaths() {
		List<String> paths = new ArrayList<String>();
		if (operatingSystem == OperatingSystem.LINUX) {
			paths.add("/bin");
			paths.add("/lib");
			paths.add("/usr/bin");
			paths.add("/usr/lib");
			paths.add("/usr/X11R6/bin");
			paths.add("/usr/X11R6/lib");
		}
		else if (CURRENT_PLATFORM == WIN_64) {
			String windir = System.getenv("SystemRoot");
			if (windir != null) {
				File syswow64 = new File(windir, "SysWOW64");
				if (syswow64.isDirectory()) {
					paths.add(syswow64.getAbsolutePath());
				}
			}
		}
		return paths;
	}

	@Override
	public String toString() {
		return operatingSystem.toString() + " " + architecture.toString();
	}

	private static Platform findCurrentPlatform() {
		for (Platform platform : values()) {
			if (matchesCurrentPlatform(platform)) {
				return platform;
			}
		}
		return UNSUPPORTED;
	}

	private static boolean matchesCurrentPlatform(Platform platform) {
		if (platform.operatingSystem == OperatingSystem.CURRENT_OPERATING_SYSTEM) {
			if (platform.architecture == Architecture.CURRENT_ARCHITECTURE) {
				return true;
			}
		}
		return false;
	}

	public String getExecutableExtension() {
		return executableExtension;
	}
}
