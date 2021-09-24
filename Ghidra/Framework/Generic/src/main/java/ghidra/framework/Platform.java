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
	 * Identifies a Windows x86 32-bit OS.
	 */
	WIN_X86_32(OperatingSystem.WINDOWS, Architecture.X86, "win_x86_32", ".dll", ".exe"),

	/**
	 * Identifies a Windows x86 64-bit OS.
	 */
	WIN_X86_64(OperatingSystem.WINDOWS, Architecture.X86_64, "win_x86_64", ".dll", ".exe"),

	/**
	 * Identifies a Linux x86 32-bit OS.
	 */
	LINUX_X86_32(OperatingSystem.LINUX, Architecture.X86, "linux_x86_32", ".so", ""),

	/**
	 * Identifies a Linux x86 64-bit OS.
	 */
	LINUX_X86_64(OperatingSystem.LINUX, Architecture.X86_64, "linux_x86_64", ".so", ""),

	/**
	 * Identifies a Linux ARM 64-bit OS.
	 */
	LINUX_ARM_64(OperatingSystem.LINUX, Architecture.ARM_64, "linux_arm_64", ".so", ""),

	/**
	 * Identifies a macOS x86 32-bit OS.
	 */
	MAC_X86_32(OperatingSystem.MAC_OS_X, Architecture.X86, "mac_x86_32", ".dylib", ""),

	/**
	 * Identifies a macOS x86 64-bit OS.
	 */
	MAC_X86_64(OperatingSystem.MAC_OS_X, Architecture.X86_64, "mac_x86_64", ".dylib", ""),

	/**
	 * Identifies a macOS ARM 64-bit OS.
	 */
	MAC_ARM_64(OperatingSystem.MAC_OS_X, Architecture.ARM_64, "mac_arm_64", ".so", ""),

	/**
	 * Identifies an unsupported OS.
	 */
	UNSUPPORTED(OperatingSystem.UNSUPPORTED, Architecture.UNKNOWN, null, null, ""),

	/**
	 * Identifies a Windows 64-bit OS.
	 * 
	 * @deprecated Use {@link #WIN_X86_64} instead.
	 */
	@Deprecated(since = "10.1", forRemoval = true)
	WIN_64(OperatingSystem.WINDOWS, Architecture.X86_64, "win_x86_64", ".dll", ".exe"),
	
	/**
	 * Identifies a Windows OS, the architecture for which we do not know or have not encountered.
	 * We'll treat it as {@link #WIN_X86_64} and hope for the best.
	 * 
	 * @deprecated Unknown architectures are not supported
	 */
	@Deprecated(since = "10.1", forRemoval = true)
	WIN_UNKOWN(OperatingSystem.WINDOWS, Architecture.UNKNOWN, "win_x86_64", ".dll", ".exe"),

	/**
	 * Identifies a Linux X86 32-bit OS.
	 * 
	 * @deprecated Use {@link #LINUX_X86_32} instead.
	 */
	@Deprecated(since = "10.1", forRemoval = true)
	LINUX(OperatingSystem.LINUX, Architecture.X86, "linux_x86_32", ".so", ""),

	/**
	 * Identifies a Linux X86 64-bit OS.
	 * 
	 * @deprecated Use {@link #LINUX_X86_64} instead.
	 */
	@Deprecated(since = "10.1", forRemoval = true)
	LINUX_64(OperatingSystem.LINUX, Architecture.X86_64, "linux_x86_64", ".so", ""),
	
	/**
	 * Identifies a Linux OS, the architecture for which we do not know or have not encountered.
	 * We'll treat it as {@link #LINUX_X86_64} and hope for the best.
	 * 
	 * @deprecated Unknown architectures are not supported
	 */
	@Deprecated(since = "10.1", forRemoval = true)
	LINUX_UKNOWN(OperatingSystem.LINUX, Architecture.UNKNOWN, "linux_x86_64", ".so", ""),

	/**
	 * Identifies a macOS X86 32-bit OS.
	 * 
	 * @deprecated Use {@link #MAC_OSX_32} instead.
	 */
	@Deprecated(since = "10.1", forRemoval = true)
	MAC_OSX_32(OperatingSystem.MAC_OS_X, Architecture.X86, "mac_x86_32", ".dylib", ""),

	/**
	 * Identifies a macOS X86 64-bit OS.
	 * 
	 * @deprecated Use {@link #MAC_X86_64} instead.
	 */
	@Deprecated(since = "10.1", forRemoval = true)
	MAC_OSX_64(OperatingSystem.MAC_OS_X, Architecture.X86_64, "mac_x86_64", ".dylib", ""),
	
	/**
	 * Identifies a macOS OS, the architecture for which we do not know or have not encountered.
	 * We'll treat it as {@link #MAC_X86_64} and hope for the best.
	 * 
	 * @deprecated Use {@link #MAC_X86_64} instead.
	 */
	@Deprecated(since = "10.1", forRemoval = true)
	MAC_UNKNOWN(OperatingSystem.MAC_OS_X, Architecture.UNKNOWN, "mac_x86_64", ".dylib", "");

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
		else if (CURRENT_PLATFORM == WIN_X86_64) {
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
