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
package mdemangler;

/**
 * An MDMang extension that tailors output to Visual Studio 2013 (and earlier?) output results.
 */
public class MDMangVS2013 extends MDMangVS2015 {

	/******************************************************************************/
	// SPECIALIZATION METHODS
	@Override
	public boolean allowCVModLRefRRef() {
		return false;
	}
}

/******************************************************************************/
/******************************************************************************/
