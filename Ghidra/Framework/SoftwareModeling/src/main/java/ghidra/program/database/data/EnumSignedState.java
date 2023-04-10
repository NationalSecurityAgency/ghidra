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
package ghidra.program.database.data;

/**
 * Keeps track of the signed state of an enum datatype. Enum are fundamentally either signed or
 * unsigned, but sometimes you can't tell based on the values they contain. Once a negative value
 * is added, then the enum becomes locked as signed, preventing high unsigned values from being 
 * added. Once a high value unsigned value is added, then it becomes locked as unsigned value. If
 * neither a negative value or high unsigned value has been added, then the enum is not locked as
 * either signed or unsigned.
 */
public enum EnumSignedState {
	SIGNED, 	// Enum contains at least 1 negative value, preventing high unsigned values
	UNSIGNED,   // Enum contains at least 1 high unsigned value, preventing negative values
	NONE	    // Enum contains neither a negative or a high unsigned value, so can go either way
}
