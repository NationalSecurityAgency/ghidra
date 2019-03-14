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
package ghidra.app.util.bin.format.macho.prelink;

import java.util.*;

public class PrelinkMap {

	private Map<String, Object> map = new HashMap<String, Object>();

	public void put( String key, String value ) {
		map.put( key, value );
	}
	public void put( String key, long value ) {
		map.put( key, value );
	}
	public void put( String key, boolean value ) {
		map.put( key, value );
	}
	public void put( String key, PrelinkMap value ) {
		map.put( key, value );
	}

	public String getPrelinkBundlePath() {
		Object value = map.get( PrelinkConstants.kPrelinkBundlePathKey );
		if ( value instanceof String ) {
			return (String)value;
		}
		return null;
	}

	public String getPrelinkUUID() {
		Object value = map.get( PrelinkConstants.kPrelinkInterfaceUUIDKey );
		if ( value instanceof String ) {
			return (String)value;
		}
		return null;
	}

	public long getPrelinkKmodInfo() {
		Object value = map.get( PrelinkConstants.kPrelinkKmodInfoKey );
		if ( value instanceof Long ) {
			return (Long)value;
		}
		if ( value instanceof Integer ) {
			return (Integer)value + 0xffffffffL;
		}
		return -1;
	}

	public long getPrelinkExecutable() {
		Object value = map.get( PrelinkConstants.kPrelinkExecutableKey );
		if ( value instanceof Long ) {
			return (Long)value;
		}
		if ( value instanceof Integer ) {
			return (Integer)value + 0xffffffffL;
		}
		return -1;
	}

	public long getPrelinkExecutableSize() {
		Object value = map.get( PrelinkConstants.kPrelinkExecutableSizeKey );
		if ( value instanceof Long ) {
			return (Long)value;
		}
		if ( value instanceof Integer ) {
			return (Integer)value + 0xffffffffL;
		}
		return -1;
	}

	public long getPrelinkExecutableLoadAddr() {
		Object value = map.get( PrelinkConstants.kPrelinkExecutableLoadKey );
		if ( value instanceof Long ) {
			return (Long)value;
		}
		if ( value instanceof Integer ) {
			return (Integer)value + 0xffffffffL;
		}
		return -1;
	}

	public long getPrelinkModuleIndex() {
		Object value = map.get(PrelinkConstants.kPrelinkModuleIndexKey);
		if (value instanceof Long) {
			return (Long) value;
		}
		if (value instanceof Integer) {
			return (Integer) value + 0xffffffffL;
		}
		return -1;
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		List<String> keyList = new ArrayList<String>( map.keySet() );
		Collections.sort( keyList );
		Iterator<String> keyIterator = keyList.iterator();
		while ( keyIterator.hasNext() ) {
			String key = keyIterator.next();
			Object value = map.get( key );
			if ( value instanceof Long ) {
				long longValue = (Long) value;
				buffer.append( key + '=' + "0x" + Long.toHexString( longValue ) + '\n' );
			}
			else {
				buffer.append( key + '=' + value + '\n' );
			}
		}
		return buffer.toString();
	}


}
