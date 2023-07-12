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

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

/**
 *
 */
public class AddressModelDataType {//implements AddressModel {

//	/**
//	 * Emulate enum by creating static array of Address Models.
//	 */
//	private static List<AddressModel> values = new ArrayList<>(8);
//
//	@SuppressWarnings("unused")
//	private String modelName;
//	private byte ordinal;
//
//	AddressModelDataType(String name, int value) {
//		this.modelName = name;
//		this.ordinal = (byte) value;
//		try {
//			values.stream().filter(conv -> conv.name().equals(modelName)).findAny().orElseThrow();
//		} catch (NoSuchElementException e) {
//			values.add(this);
//			System.out.print("Adding Address Model ".concat(Integer.toString(ordinal)).concat(" = '")
//					.concat(modelName).concat("'\n"));
//		}
//	}
//
//	/**
//	 * Returns the AddressModel which is likely to correspond with the
//	 * specified prototype name.
//	 * @param modelName specific address model name
//	 * @return AddressModel
//	 */
//	public static AddressModel guessFromName(String modelName) {
//		if (modelName == null) {
//			return unknown;
//		}
//		modelName = modelName.toLowerCase();
//		for (AddressModel value : AddressModelDataType.values()) {
//			if (value == unknown) {
//				continue;
//			}
//			if (modelName.contains(value.name())) {
//				return value;
//			}
//		}
//		return unknown;
//	}
//
//	/**
//	 * Returns the AddressModel corresponding to the specified
//	 * ordinal.
//	 * @param ordinal generic address model ordinal
//	 * @return AddressModel
//	 */
//	public static AddressModel get(int ordinal) {
//		AddressModel[] values = AddressModelDataType.values();
//		if (ordinal >= 0 && ordinal < values.length) {
//			return values[ordinal];
//		}
//		return unknown;
//	}
//
//	/**
//	 * Part of emulation of enums
//	 */
//	@Override
//	public String name() {
//		return modelName;
//	}
//
//	/**
//	 * Part of emulation of enums
//	 */
//	@Override
//	public int ordinal() {
//		return ordinal;
//	}
//
//	/**
//	 * Part of emulation of enums
//	 */
//	public static AddressModel[] values() {
//		return values.toArray(AddressModel[]::new);
//	}
//
//	@Override
//	public void setComment(String comment) {
//		// TODO Auto-generated method stub
//
//	}
//
//	@Override
//	public String getComment() {
//		// TODO Auto-generated method stub
//		return null;
//	}

}