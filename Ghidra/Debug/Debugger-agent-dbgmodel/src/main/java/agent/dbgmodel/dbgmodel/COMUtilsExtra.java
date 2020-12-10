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
package agent.dbgmodel.dbgmodel;

import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMException;
import com.sun.jna.platform.win32.COM.COMUtils;

/**
 * Utilities for interacting with Microsoft COM objects beyond those provided by {@link COMUtils}.
 * 
 * See the MSDN for details on the meanings of the return codes for the function or method of
 * interest.
 */
public interface COMUtilsExtra {

	public static HRESULT E_UNEXPECTED = new HRESULT(0x8000FFFF);
	public static HRESULT E_BOUNDS = new HRESULT(0x8000000B);
	public static HRESULT E_NOTIMPLEMENTED = new HRESULT(0x80004001);
	public static HRESULT E_NOINTERFACE = new HRESULT(0x80004002);
	public static HRESULT E_COM_EXC = new HRESULT(0x80004003);
	public static HRESULT E_FAIL = new HRESULT(0x80004005);
	public static HRESULT E_CANTCALLOUT_INASYNCCALL = new HRESULT(0x80010004);
	public static HRESULT E_INTERNALEXCEPTION = new HRESULT(0x80040205);
	public static HRESULT E_ACCESS_DENIED = new HRESULT(0x80070005);
	public static HRESULT E_CANNOT_READ = new HRESULT(0x8007001E);
	public static HRESULT E_INVALID_PARAM = new HRESULT(0x80070057);
	public static HRESULT E_SCOPE_NOT_FOUND = new HRESULT(0x8007013E);

	/**
	 * Check if the given exception represents an {@code E_NOINTERFACE} result
	 * 
	 * @param e the exception
	 * @return true if {@code E_NOINTERFACE}
	 */
	static boolean isE_NOINTERFACE(COMException e) {
		return e.getMessage().contains("HRESULT: 80004002");
	}

	/**
	 * Check if the given exception represents an {@code E_UNEXPECTED} result
	 * 
	 * @param e the exception
	 * @return true if {@code E_UNEXPECTED}
	 */
	static boolean isE_UNEXPECTED(COMException e) {
		return e.getMessage().contains("HRESULT: 8000ffff");
	}

	/**
	 * Check if the given exception represents an {@code E_INTERNALEXCEPTION} result
	 * 
	 * @param e the exception
	 * @return true if {@code E_INTERNALEXCEPTION}
	 */
	static boolean isE_INTERNALEXCEPTION(COMException e) {
		return e.getMessage().contains("HRESULT: 80040205");
	}
}
