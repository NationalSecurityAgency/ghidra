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
import ghidra.app.script.GhidraScript;


public class DexWriteRegistersScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		final int MAX = 255;

		for ( int i = 0 ; i < MAX ; ++i ) {
			print( "v" + i + " " );
			if ( i % 16 == 0 ) {
				print( "\n" );	
			}
		}

		println( "---------------" );

		for ( int i = 0 ; i < MAX ; i += 2 ) {
			print( "vw" + i + " _ " );
			if ( i != 0 && i % 14 == 0 ) {
				print( "\n" );	
			}
		}

		println( "---------------" );

		int count = 0;
		for ( int i = 1 ; i < MAX ; i += 2 ) {
			print( "_ vw" + i + " " );
			++count;
			if ( count == 8 ) {
				print( "\n" );
				count = 0;
			}
		}

		println( "---------------" );
	}

}
