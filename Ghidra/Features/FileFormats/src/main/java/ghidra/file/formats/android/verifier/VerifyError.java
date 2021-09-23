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
package ghidra.file.formats.android.verifier;

/**
 * https://android.googlesource.com/platform/art/+/master/runtime/verifier/verifier_enums.h
 */
public final class VerifyError {

	public final static int VERIFY_ERROR_BAD_CLASS_HARD = 1 << 0;

	public final static int VERIFY_ERROR_BAD_CLASS_SOFT = 1 << 1;

	public final static int VERIFY_ERROR_NO_CLASS = 1 << 2;

	public final static int VERIFY_ERROR_NO_FIELD = 1 << 3;

	public final static int VERIFY_ERROR_NO_METHOD = 1 << 4;

	public final static int VERIFY_ERROR_ACCESS_CLASS = 1 << 5;

	public final static int VERIFY_ERROR_ACCESS_FIELD = 1 << 6;

	public final static int VERIFY_ERROR_ACCESS_METHOD = 1 << 7;

	public final static int VERIFY_ERROR_CLASS_CHANGE = 1 << 8;

	public final static int VERIFY_ERROR_INSTANTIATION = 1 << 9;

	public final static int VERIFY_ERROR_FORCE_INTERPRETER = 1 << 10;

	public final static int VERIFY_ERROR_LOCKING = 1 << 11;

	public final static int VERIFY_ERROR_SKIP_COMPILER = 1 << 31;
}
