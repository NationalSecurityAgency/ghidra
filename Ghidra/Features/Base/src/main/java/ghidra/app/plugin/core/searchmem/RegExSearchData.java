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
package ghidra.app.plugin.core.searchmem;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class RegExSearchData extends SearchData {
	private Pattern pattern;
	
	public static RegExSearchData createRegExSearchData( String inputString ) {
	    RegExSearchData regExSearchData = new RegExSearchData( inputString );
	    if ( regExSearchData.errorMessage != null ) {
	        throw new IllegalArgumentException( "Problem creating search data: " + 
	            regExSearchData.errorMessage );
	    }
	    return regExSearchData;
	}
	
	public RegExSearchData(String inputString) {
		super(inputString, new byte[0], null);		
		try {
			pattern = Pattern.compile(inputString, Pattern.DOTALL);
		} catch (PatternSyntaxException pse) {
			errorMessage = pse.getMessage();
		}
	}

	@Override
    public boolean isValidSearchData() {
		return pattern != null;
	}
	public Pattern getRegExPattern() {
		return pattern;
	}
}
