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

import java.awt.GraphicsEnvironment;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;

import ghidra.framework.OperatingSystem;

/**
 * Standalone helper application which displays the Windows-native certificate manager
 * dialog via the {@code CryptUIDlgCertMgr} Win32 API using Project Panama (FFM API).
 */
public class WindowsCertMgrApp {

	/**
	 * Memory layout for {@code CRYPTUI_CERT_MGR_STRUCT}:
	 * <pre>
	 * typedef struct _CRYPTUI_CERT_MGR_STRUCT {
	 *   DWORD     dwSize;
	 *   HWND      hwndParent;
	 *   DWORD     dwFlags;
	 *   LPCWSTR   pwszTitle;
	 *   LPCSTR    pszInitUsageOID;
	 * } CRYPTUI_CERT_MGR_STRUCT;
	 * </pre>
	 */
	private static final StructLayout CRYPTUI_CERT_MGR_STRUCT_LAYOUT = MemoryLayout.structLayout(
		ValueLayout.JAVA_INT.withName("dwSize"),
		MemoryLayout.paddingLayout(4), // Padding to align pointer/address field on 64-bit Windows
		ValueLayout.ADDRESS.withName("hwndParent"),
		ValueLayout.JAVA_INT.withName("dwFlags"),
		MemoryLayout.paddingLayout(4), // Padding for alignment before the next address pointer
		ValueLayout.ADDRESS.withName("pwszTitle"),
		ValueLayout.ADDRESS.withName("pszInitUsageOID"));

	// VarHandles for accessing struct fields cleanly
	private static final VarHandle VH_DW_SIZE = CRYPTUI_CERT_MGR_STRUCT_LAYOUT.varHandle(
		MemoryLayout.PathElement.groupElement("dwSize"));
	private static final VarHandle VH_HWND_PARENT = CRYPTUI_CERT_MGR_STRUCT_LAYOUT.varHandle(
		MemoryLayout.PathElement.groupElement("hwndParent"));
	private static final VarHandle VH_DW_FLAGS = CRYPTUI_CERT_MGR_STRUCT_LAYOUT.varHandle(
		MemoryLayout.PathElement.groupElement("dwFlags"));
	private static final VarHandle VH_PWSZ_TITLE = CRYPTUI_CERT_MGR_STRUCT_LAYOUT.varHandle(
		MemoryLayout.PathElement.groupElement("pwszTitle"));
	private static final VarHandle VH_PSZ_INIT_USAGE_OID = CRYPTUI_CERT_MGR_STRUCT_LAYOUT.varHandle(
		MemoryLayout.PathElement.groupElement("pszInitUsageOID"));

	/**
	 * Layout of the buffer which receives the call state captured by the downcall below.  The
	 * last-error value is held in thread-local storage, and the runtime may execute code which
	 * overwrites it between the downcall and any later attempt to read it, so it must be captured
	 * as part of the call itself rather than retrieved by a separate call to {@code GetLastError}.
	 */
	private static final StructLayout CAPTURED_STATE_LAYOUT = Linker.Option.captureStateLayout();

	private static final VarHandle VH_LAST_ERROR = CAPTURED_STATE_LAYOUT
			.varHandle(MemoryLayout.PathElement.groupElement("GetLastError"));

	private static final MethodHandle CRYPT_UI_DLG_CERT_MGR;

	static {
		Linker linker = Linker.nativeLinker();
		try {
			SymbolLookup cryptUiLib = SymbolLookup.libraryLookup("cryptui", Arena.global());

			// cryptui.dll exports this symbol undecorated - there is no separate W/A pair, the
			// wide/ANSI distinction is carried by the struct fields instead.  BOOL is a 32-bit
			// int, so JAVA_INT rather than JAVA_BOOLEAN (a single byte) describes the result.
			// Capturing GetLastError adds a leading buffer parameter to the resulting handle.
			CRYPT_UI_DLG_CERT_MGR = linker.downcallHandle(
				cryptUiLib.find("CryptUIDlgCertMgr").orElseThrow(),
				FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS),
				Linker.Option.captureCallState("GetLastError"));
		}
		catch (Throwable e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	public static void main(String[] args) {

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM != OperatingSystem.WINDOWS) {
			System.err.println(
				"WinCertMgrApp may only be launched on Windows (detected: " +
					OperatingSystem.CURRENT_OPERATING_SYSTEM + ")");
			System.exit(1);
		}

		if (GraphicsEnvironment.isHeadless()) {
			System.err.println("WinCertMgrApp requires a graphical environment");
			System.exit(1);
		}

		// Use an Arena to manage native memory allocation safely and scoped
		try (Arena arena = Arena.ofConfined()) {
			// Allocate memory for the structure
			MemorySegment structSegment = arena.allocate(CRYPTUI_CERT_MGR_STRUCT_LAYOUT);

			// Allocate null-terminated wide string (LPCWSTR) for the title.  The charset must be
			// given: allocateFrom(String) encodes as UTF-8 with a single-byte terminator, which a
			// wide string reader would interpret as garbage and scan past looking for a 16-bit NUL.
			MemorySegment titleSegment =
				arena.allocateFrom("Certificate Manager", StandardCharsets.UTF_16LE);

			// Populate fields using the layout's VarHandles
			VH_DW_SIZE.set(structSegment, 0L, (int) CRYPTUI_CERT_MGR_STRUCT_LAYOUT.byteSize());
			VH_HWND_PARENT.set(structSegment, 0L, MemorySegment.NULL);
			VH_DW_FLAGS.set(structSegment, 0L, 0);
			VH_PWSZ_TITLE.set(structSegment, 0L, titleSegment);
			VH_PSZ_INIT_USAGE_OID.set(structSegment, 0L, MemorySegment.NULL); // null pointer filter

			// Receives the last-error value captured as part of the call below
			MemorySegment capturedState = arena.allocate(CAPTURED_STATE_LAYOUT);

			try {
				int result =
					(int) CRYPT_UI_DLG_CERT_MGR.invokeExact(capturedState, structSegment);
				if (result == 0) {		// BOOL: zero indicates failure
					int lastError = (int) VH_LAST_ERROR.get(capturedState, 0L);
					System.err.println("CryptUIDlgCertMgr failed (GetLastError=" + lastError + ")");
					System.exit(1);
				}
			}
			catch (Throwable t) {
				System.err.println("Failed to execute native method invocation:");
				t.printStackTrace();
				System.exit(1);
			}

		}
	}

	private WindowsCertMgrApp() {
		// entry point only
	}
}
