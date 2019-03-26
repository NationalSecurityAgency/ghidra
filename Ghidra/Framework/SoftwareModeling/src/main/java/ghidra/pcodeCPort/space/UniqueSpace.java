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
package ghidra.pcodeCPort.space;

import ghidra.pcodeCPort.translate.*;

import java.io.PrintStream;


public class UniqueSpace extends AddrSpace {
	public UniqueSpace( Translate t, String nm, int ind, int fl ) {
		super( t, spacetype.IPTR_INTERNAL, nm, 4, 1, ind, fl, 0 );

		setFlags( hasphysical );
	}

	public UniqueSpace( Translate t ) {
		super( t, spacetype.IPTR_INTERNAL );

		setFlags( hasphysical );
	}

	@Override
    public void saveXml( PrintStream s ) {
		s.print( "<space_unique" );
		save_basic_attributes( s );
		s.println( "/>" );
	}

}
