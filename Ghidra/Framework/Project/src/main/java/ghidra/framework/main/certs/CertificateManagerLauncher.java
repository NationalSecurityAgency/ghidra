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
package ghidra.framework.main.certs;

import java.io.File;
import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.CodeSource;
import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.framework.OperatingSystem;
import ghidra.util.Msg;

/**
 * Launches (or refocuses) the OS-native certificate manager used to view/manage the
 * user's trusted CA certificates &mdash; the same tool Chrome/Edge expose via their own
 * "Manage certificates" button. Supported on Windows and macOS only.
 * <p>
 * Windows: displays the native {@code CryptUIDlgCertMgr} dialog via {@link WindowsCertMgrApp},
 * launched as an independent Java process (that call blocks until the dialog is closed, so
 * it must not run inside Ghidra's own JVM). A subsequent call while that process is still
 * alive brings its window to the foreground instead of starting a second one.
 * <p>
 * macOS: launches Keychain Access via {@code open -a}, which itself focuses an
 * already-running instance instead of starting a duplicate.
 */
public class CertificateManagerLauncher {

	private static Process lastWindowsProcess;

	/**
	 * Launch the platform certificate manager, or bring an already-launched instance to the
	 * foreground. Safe to call repeatedly/rapidly from the Swing thread; a single
	 * {@code synchronized} entry point is sufficient serialization since every operation
	 * performed here (starting a process, enumerating windows) returns quickly.
	 */
	public static synchronized void launchOrFocus() {
		try {
			switch (OperatingSystem.CURRENT_OPERATING_SYSTEM) {
				case OperatingSystem.WINDOWS:
					launchOrFocusWindows();
					break;
				case OperatingSystem.MAC_OS_X:
					new ProcessBuilder("open", "-a", "Keychain Access").start();
					break;
				default:
					Msg.warn(CertificateManagerLauncher.class,
							"Manage CA Certificates is not supported on " + OperatingSystem.CURRENT_OPERATING_SYSTEM);
			}
		}
		catch (IOException e) {
			Msg.showError(CertificateManagerLauncher.class, null, "Manage CA Certificates",
				"Unable to launch the system certificate manager", e);
		}
	}

	private static void launchOrFocusWindows() throws IOException {

		if (lastWindowsProcess != null && lastWindowsProcess.isAlive() &&
			focusWindow(lastWindowsProcess.pid())) {
			return;
		}

		String javaBin =
			System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";

		// WindowsCertMgrApp uses the FFM API (Project Panama) to call cryptui.dll.  Its restricted
		// methods produce a warning on JDK 21+, and will become a hard error in a future release,
		// unless native access is explicitly enabled.  The application runs on the classpath (the
		// unnamed module), so native access is granted to ALL-UNNAMED.  This is the JDK-sanctioned
		// opt-in, not a temporary workaround.  The flag must be passed here because this child JVM
		// does not inherit the parent's launch arguments.
		ProcessBuilder builder = new ProcessBuilder(javaBin, "--enable-native-access=ALL-UNNAMED",
			"-cp", getHelperClasspath(), WindowsCertMgrApp.class.getName());

		builder.inheritIO();
		lastWindowsProcess = builder.start();
	}

	/**
	 * Establish the classpath required by the {@link WindowsCertMgrApp} helper process, which is
	 * the code source of that class together with the code source of each class it relies upon.
	 * <p>
	 * The helper needs very little, so Ghidra's own classpath is not passed on: it names every
	 * module of the installation, which is both unnecessary here and long enough to approach the
	 * length limit which Windows imposes upon a command line.
	 *
	 * @return the classpath for the helper process
	 * @throws IOException if the location of a required class cannot be determined
	 */
	private static String getHelperClasspath() throws IOException {

		// The helper application and the classes it uses; each contributes its code source, which
		// resolves to a module jar within an installation or to a class directory in development
		Class<?>[] required = { WindowsCertMgrApp.class, OperatingSystem.class };

		Set<String> classpath = new LinkedHashSet<>();
		for (Class<?> c : required) {
			CodeSource codeSource = c.getProtectionDomain().getCodeSource();
			URL location = codeSource != null ? codeSource.getLocation() : null;
			if (location == null) {
				throw new IOException("Unable to determine the location of " + c.getName());
			}
			try {
				classpath.add(new File(location.toURI()).getAbsolutePath());
			}
			catch (URISyntaxException e) {
				throw new IOException("Invalid location for " + c.getName() + ": " + location, e);
			}
		}
		return String.join(File.pathSeparator, classpath);
	}

	/**
	 * Win32 bindings used to locate and focus an existing certificate manager window.
	 * <p>
	 * These are established within a nested class so that they are initialized when first used,
	 * which only occurs on Windows.  Establishing them within {@link CertificateManagerLauncher}
	 * itself would fail on every other platform and would prevent the macOS branch of
	 * {@link #launchOrFocus()} from running.
	 */
	private static final class Win32 {

		/** {@code BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)} */
		private static final FunctionDescriptor ENUM_PROC_DESCRIPTOR = FunctionDescriptor
				.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);

		private static final MethodHandle ENUM_WINDOWS;
		private static final MethodHandle GET_WINDOW_THREAD_PROCESS_ID;
		private static final MethodHandle SET_FOREGROUND_WINDOW;
		private static final MethodHandle ENUM_PROC;

		static {
			Linker linker = Linker.nativeLinker();
			SymbolLookup user32 = SymbolLookup.libraryLookup("user32", Arena.global());

			// BOOL EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam)
			ENUM_WINDOWS = linker.downcallHandle(user32.find("EnumWindows").orElseThrow(),
				FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
					ValueLayout.JAVA_LONG));

			// DWORD GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId)
			GET_WINDOW_THREAD_PROCESS_ID =
				linker.downcallHandle(user32.find("GetWindowThreadProcessId").orElseThrow(),
					FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
						ValueLayout.ADDRESS));

			// BOOL SetForegroundWindow(HWND hWnd)
			SET_FOREGROUND_WINDOW =
				linker.downcallHandle(user32.find("SetForegroundWindow").orElseThrow(),
					FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

			try {
				ENUM_PROC = MethodHandles.lookup().findStatic(CertificateManagerLauncher.class,
					"enumWindowsProc",
					MethodType.methodType(int.class, MemorySegment.class, long.class));
			}
			catch (ReflectiveOperationException e) {
				throw new ExceptionInInitializerError(e);
			}
		}

		private Win32() {
			// no construct
		}
	}

	// State for the EnumWindows callback below.  Its use is confined to focusWindow, which is only
	// reached from the synchronized launchOrFocus entry point.
	private static long searchProcessId;
	private static MemorySegment searchProcessIdOut;
	private static long foundWindowHandle;

	/**
	 * {@code EnumWindows} callback which records the first top-level window belonging to the
	 * process being searched for and then halts the enumeration.
	 *
	 * @param hwnd handle of the window supplied by the enumeration
	 * @param lParam application defined value, unused
	 * @return zero (FALSE) to halt the enumeration, non-zero (TRUE) to continue it
	 */
	private static int enumWindowsProc(MemorySegment hwnd, long lParam) {
		try {
			int threadId =
				(int) Win32.GET_WINDOW_THREAD_PROCESS_ID.invokeExact(hwnd, searchProcessIdOut);
			if (threadId != 0 && Integer.toUnsignedLong(
				searchProcessIdOut.get(ValueLayout.JAVA_INT, 0)) == searchProcessId) {
				foundWindowHandle = hwnd.address();
				return 0;		// FALSE: the window was found, halt the enumeration
			}
		}
		catch (Throwable t) {
			// disregard this window and continue with the next
		}
		return 1;				// TRUE: continue the enumeration
	}

	/**
	 * Bring the top-level window owned by the given process to the foreground.
	 *
	 * @param pid the process ID whose window should be focused
	 * @return true if a window was found and focused
	 */
	private static boolean focusWindow(long pid) {

		try (Arena arena = Arena.ofConfined()) {

			searchProcessId = pid;
			searchProcessIdOut = arena.allocate(ValueLayout.JAVA_INT);
			foundWindowHandle = 0;

			MemorySegment enumProc = Linker.nativeLinker()
					.upcallStub(Win32.ENUM_PROC, Win32.ENUM_PROC_DESCRIPTOR, arena);

			// EnumWindows reports FALSE when the callback halts the enumeration, which is the
			// outcome sought here, so its result does not indicate success or failure
			int enumerated = (int) Win32.ENUM_WINDOWS.invokeExact(enumProc, 0L);
			Msg.trace(CertificateManagerLauncher.class,
				"EnumWindows returned " + enumerated + " while searching for process " + pid);

			if (foundWindowHandle == 0) {
				return false;
			}
			int focused = (int) Win32.SET_FOREGROUND_WINDOW
					.invokeExact(MemorySegment.ofAddress(foundWindowHandle));
			return focused != 0;
		}
		catch (Throwable t) {
			// Includes a failure to establish the Win32 bindings; the caller then launches a new
			// certificate manager process rather than focusing the existing one
			Msg.debug(CertificateManagerLauncher.class,
				"Unable to focus the existing certificate manager window", t);
			return false;
		}
		finally {
			searchProcessIdOut = null;		// the arena which allocated it has been closed
		}
	}

	private CertificateManagerLauncher() {
		// static utility
	}
}
