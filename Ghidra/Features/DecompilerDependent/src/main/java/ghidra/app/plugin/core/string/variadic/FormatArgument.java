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
package ghidra.app.plugin.core.string.variadic;
/**
 * This class represents a single argument of a variadic function
 */
public class FormatArgument {

	private String lengthModifier;
	private String conversionSpecifier;

	/**
	 * Constructor for a FormatArg
	 * 
	 * @param lengthModifier length modifier of a format argument
	 * @param conversionSpec conversion specifier of a format argument
	 */
	public FormatArgument(String lengthModifier, String conversionSpec) {
		this.lengthModifier = lengthModifier;
		this.conversionSpecifier = conversionSpec;
	}

	/**
	 * lenghtModifier getter
	 * 
	 * @return lengthModifier
	 */
	public String getLengthModifier() {
		return this.lengthModifier;
	}

	/**
	 * convertionSpec getter
	 * 
	 * @return conversionSpecifier
	 */
	public String getConversionSpecifier() {
		return this.conversionSpecifier;
	}

	/**
	 * Converts FormatArg to String
	 * 
	 * @return FormatArgument as String
	 */
	public String toString() {

		return String.format("[%s, %s]", this.lengthModifier, this.conversionSpecifier);
	}
}
