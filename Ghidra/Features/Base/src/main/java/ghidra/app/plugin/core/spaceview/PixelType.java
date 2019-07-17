/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.spaceview;

public enum PixelType {
	UNUSED_TYPE,
	ERROR,

	UNINIT_UNUSED,
	UNINIT_DATA,

	EXTERNAL,

	UNDEF_DATA0,
	UNDEF_DATA1,
	UNDEF_DATA2,
	UNDEF_DATA3,
	UNDEF_DATA4,
	UNDEF_DATA5,
	UNDEF_DATA6,
	UNDEF_DATA7,

	DEF_DATA0,
	DEF_DATA1,
	DEF_DATA2,
	DEF_DATA3,
	DEF_DATA4,
	DEF_DATA5,
	DEF_DATA6,
	DEF_DATA7,

	CODE_MEMORY,
	CODE_FLOW,
	CODE_SPECIAL,
	CODE_NORMAL,

	FUN_CODE_MEMORY,
	FUN_CODE_FLOW,
	FUN_CODE_SPECIAL,
	FUN_CODE_NORMAL,

	SELECTED,
	HIGHLIGHTED,
	SEL_AND_HIGH;

	public byte type() {
		return (byte) ordinal();
	}
}
