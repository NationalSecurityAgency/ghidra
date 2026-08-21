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
package ghidra.features.base.quickfix;

/**
 * Enum for the possible status values of a {@link QuickFix}.
 */
public enum QuickFixStatus {
	NONE,		// The item is unapplied and is ready to be executed
	WARNING,	// The item is unapplied and has an associated warning
	CHANGED, 	// The item is unapplied, but has changed from its original value
	DELETED,	// The item's target program element no longer exists
	ERROR,		// The item can't be applied. This may occur before or after it is applied
	DONE		// The item has been applied
}
