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

package ghidra.program.model.data;

/**
 *
 */
public enum AddressModel {
	unknown(""),
	near("near"),
	far("far"),
	huge("huge");

	@SuppressWarnings("unused")
	private String modelName;

	private AddressModel(String name) {
		this.modelName = name;
	}

	/**
	 * Returns the AddressModel which is likely to correspond with the
	 * specified prototype name.
	 * @param modelName specific address model name
	 * @return AddressModel
	 */
	public static AddressModel guessFromName(String modelName) {
		if (modelName == null) {
			return unknown;
		}
		modelName = modelName.toLowerCase();
		for (AddressModel value : AddressModel.values()) {
			if (value == unknown) {
				continue;
			}
			if (modelName.contains(value.name())) {
				return value;
			}
		}
		return unknown;
	}

	/**
	 * Returns the AddressModel corresponding to the specified
	 * ordinal.
	 * @param ordinal generic address model ordinal
	 * @return AddressModel
	 */
	public static AddressModel get(int ordinal) {
		AddressModel[] values = AddressModel.values();
		if (ordinal >= 0 && ordinal < values.length) {
			return values[ordinal];
		}
		return unknown;
	}

}
