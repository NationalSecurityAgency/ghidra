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
package ghidra.app.util.viewer.format;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.MnemonicFieldFactory;
import ghidra.util.Msg;

public class FieldFactoryNameMapper {

	private static Map<String, FieldFactory> deprecatedFieldNameToFactoryMap;

	public static FieldFactory getFactoryPrototype(String fieldName,
			FieldFactory[] prototypeFactories) {
		if (fieldName == null) {
			return null;
		}

		for (int i = 0; i < prototypeFactories.length; i++) {
			if (prototypeFactories[i].getFieldName().equals(fieldName)) {
				return prototypeFactories[i];
			}
		}

		Map<String, FieldFactory> deprecatedfactories = getDeprecatedFieldFactories();
		return deprecatedfactories.get(fieldName.toLowerCase());
	}

	private static Map<String, FieldFactory> getDeprecatedFieldFactories() {
		if (deprecatedFieldNameToFactoryMap == null) {
			deprecatedFieldNameToFactoryMap = new HashMap<String, FieldFactory>();
			deprecatedFieldNameToFactoryMap.put("mnemonic",
				createInstance(MnemonicFieldFactory.class));
		}

		return deprecatedFieldNameToFactoryMap;
	}

	private static FieldFactory createInstance(Class<? extends FieldFactory> factoryClass) {
		try {
			return factoryClass.newInstance();
		}
		catch (IllegalAccessException e) {
		}
		catch (InstantiationException e) {
		}
		catch (Exception e) {
			Msg.error(FieldFactoryNameMapper.class, "Unexpected Exception: " + e.getMessage(), e);
		}
		return null;
	}
}
