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
package ghidra.xtext.sleigh.converter;

import java.math.BigInteger;

import org.eclipse.xtext.common.services.DefaultTerminalConverters;
import org.eclipse.xtext.conversion.IValueConverter;
import org.eclipse.xtext.conversion.ValueConverter;
import org.eclipse.xtext.conversion.ValueConverterException;
import org.eclipse.xtext.conversion.impl.INTValueConverter;
import org.eclipse.xtext.nodemodel.INode;
import org.eclipse.xtext.util.Strings;

import com.google.inject.Inject;

public class SleighValueConverter extends DefaultTerminalConverters {
	
	@Inject
	private IntValueConverter hexValueConverter;
	
	@ValueConverter(rule = "HEXVAL")
	public IValueConverter<BigInteger> HEXVAL() {
		return hexValueConverter;
	}
	
	@Inject
	private IntValueConverter numValueConverter;
	
	@ValueConverter(rule = "NUMVAL")
	public IValueConverter<BigInteger> NUMVAL() {
		return numValueConverter;
	}
	
	@Inject
	private IntValueConverter binValueConverter;
	
	@ValueConverter(rule = "BINVAL")
	public IValueConverter<BigInteger> BINVAL() {
		return binValueConverter;
	}
}
