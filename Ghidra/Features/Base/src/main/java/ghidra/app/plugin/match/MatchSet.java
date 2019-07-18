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
/*
 * Created on Jun 13, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.plugin.match;

import java.util.Arrays;
import java.util.HashSet;


/**
 * 
 *
 * To change the template for this generated type comment go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */

/** class that contains a collection of matches. */
public class MatchSet extends HashSet<Match>
{
	public final String thisName;
	public final String otherName;
	
	/**
	 * @param thisProgramName Name of this program (i.e. the program from 
	 * which the matching was initiated.
	 * @param otherProgramName Name of the program being matched.
	 */
	public MatchSet( String thisProgramName, String otherProgramName )
	{
		super();
		this.thisName = thisProgramName;
		this.otherName = otherProgramName;
	}
		
	/**
	 * @return The sorted array of matches.
	 */
	public Match[] getMatches()
	{
		Match[] theMatches = this.toArray(new Match[0]);
		Arrays.sort( theMatches );
		return theMatches;
	}
	/**
	 * @return The match as an Object array.
	 */
	public Object[] getResultsArray(Match m) {
		Object[] a = new Object[5];
		a[0] = m.getThisBeginning();
		a[1] = thisName;
		a[2] = m.getOtherBeginning();
		a[3] = otherName;
		a[4] = new Integer( m.length() );
		return a;
	}
		
}


