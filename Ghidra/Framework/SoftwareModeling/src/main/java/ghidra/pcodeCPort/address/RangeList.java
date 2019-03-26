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
package ghidra.pcodeCPort.address;

import java.io.PrintStream;
import java.util.List;

import org.jdom.Element;

import generic.stl.*;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.Utils;


public class RangeList {

	private SetSTL<Range> tree;

	public RangeList( RangeList rangeList ) {
		tree = new SetSTL<>( rangeList.tree );
	}

	public RangeList() {
		tree = new ComparableSetSTL<>();
	}

	public void clear() {
		tree.clear();
	}
	public IteratorSTL<Range> begin() {
		return tree.begin();
	}
	public IteratorSTL<Range> end() {
		return tree.end();
	}

	public boolean empty() {
		return tree.isEmpty();
	}

	// tree is disjoint list of ranges
	public void insertRange( AddrSpace spc, long first, long last ) {
		// insert a new range

		// we must have iter1.first > first
		IteratorSTL<Range> iter1 = tree.upper_bound( new Range( spc, first, first ) );

		// Set iter1 to first range with range.last >=first
		// It is either current iter1 or the one before
		if ( !iter1.isBegin() ) {
			iter1.decrement();
			if ( (!iter1.get().getSpace().equals( spc ))
					|| (Utils.unsignedCompare( iter1.get().getLast(), first ) < 0) ) {
				iter1.increment();
			}
		}

		// Set iter2 to first range with range.first > last
		IteratorSTL<Range> iter2 = tree.upper_bound( new Range( spc, last, last ) );

		while ( !iter1.equals( iter2 ) ) {
			if ( Utils.unsignedCompare( iter1.get().getFirst(), first ) < 0 ) {
				first = iter1.get().getFirst();
			}
			if ( Utils.unsignedCompare( iter1.get().getLast(), last ) > 0 ) {
				last = iter1.get().getLast();
			}
			tree.erase(iter1);
			iter1.increment();
		}
		tree.insert( new Range( spc, first, last ) );

	}

	// remove a range
	public void removeRange( AddrSpace spc, long first, long last ) {

		if ( tree.isEmpty() ) {
			return; // Nothing to do
		}

		// we must have iter1.first > first
		IteratorSTL<Range> iter1 = tree.upper_bound( new Range( spc, first, first ) );
		// Set iter1 to first range with range.last >=first
		// It is either current iter1 or the one before
		if ( !iter1.isBegin() ) {
			iter1.decrement();
			if ( (!iter1.get().getSpace().equals( spc ))
					|| (Utils.unsignedCompare( iter1.get().getLast(), first ) < 0) ) {
				iter1.increment();
			}
		}

		// Set iter2 to first range with range.first > last
		IteratorSTL<Range> iter2 = tree.upper_bound( new Range( spc, last, last ) );

		while ( !iter1.equals( iter2 ) ) {

			long a = iter1.get().getFirst();
			long b = iter1.get().getLast();
			tree.erase(iter1);
			iter1.increment();
			if ( Utils.unsignedCompare( a, first ) < 0 ) {
				tree.insert( new Range( spc, a, first - 1 ) );
			}
			if ( Utils.unsignedCompare( b, last ) > 0 ) {
				tree.insert( new Range( spc, last + 1, b ) );
			}
		}
	}

	// Make sure indicated range is
	// contained in the rangelist
	public boolean inRange( Address addr, int size ) {

		if ( addr.isInvalid() ) {
			return true; // We don't really care
		}
		if ( tree.isEmpty() ) {
			return false;
		}

		// iter = first range with its first > addr
		IteratorSTL<Range> iter = tree.upper_bound( new Range( addr.getSpace(), addr.getOffset(),
			addr.getOffset() ) );
		if ( iter.isBegin() ) {
			return false;
		}
		// Set iter to last range with range.first <= addr
		iter.decrement();
		// if (iter == tree.end()) // iter can't be end if non-empty
		// return false;
		if ( !iter.get().getSpace().equals( addr.getSpace() ) ) {
			return false;
		}
		if ( Utils.unsignedCompare( iter.get().getLast(), addr.getOffset() + size - 1 ) >= 0 ) {
			return true;
		}
		return false;
	}

	// Return size of biggest range (up to maxsize) starting at addr
	// which is completely covered by this rangelist
	public long longestFit( Address addr, long maxsize ) {
		if ( addr.isInvalid() ) {
			return 0;
		}
		if ( tree.isEmpty() ) {
			return 0;
		}

		// iter = first range with its first > addr
		long offset = addr.getOffset();
		IteratorSTL<Range> iter = tree.upper_bound( new Range( addr.getSpace(), offset, offset ) );
		if ( iter.isBegin() ) {
			return 0;
		}
		// Set iter to last range with range.first <= addr
		iter.decrement();
		long sizeres = 0;
		if ( Utils.unsignedCompare( iter.get().getLast(), offset ) < 0 ) {
			return sizeres;
		}
		do {
			if ( !iter.get().getSpace().equals( addr.getSpace() ) ) {
				break;
			}
			if ( Utils.unsignedCompare( iter.get().getFirst(), offset ) > 0 ) {
				break;
			}
			sizeres += (iter.get().getLast() + 1 - offset); // Size extends to end of range
			offset = iter.get().getLast() + 1; // Try to chain on the next range
			if ( Utils.unsignedCompare( sizeres, maxsize ) >= 0 ) {
				break; // Don't bother if past maxsize
			}
			iter.increment(); // Next range in the chain
		} while ( !iter.isEnd() );
		return sizeres;
	}

	public Range getFirstRange() {
		if ( tree.isEmpty() ) {
			return null;
		}
		return tree.begin().get();
	}

	public Range getFirstRange( AddrSpace spaceid ) {
		Range range = new Range(spaceid,0,0);
		IteratorSTL<Range> iter = tree.lower_bound(range);
		if (iter.equals( tree.end() ) ) {
			return null;
		}
		if ( !iter.get().getSpace().equals( spaceid ) ) {
			return null;
		}
		return iter.get();
	}

	public Range getLastRange() {
		if ( tree.isEmpty() ) {
			return null;
		}
		IteratorSTL<Range> iter = tree.end();
		iter.decrement();
		return iter.get();
	}

	public Range getLastRange( AddrSpace spaceid ) {
		Range range = new Range( spaceid, -1, -1 );
		IteratorSTL<Range> iter = tree.upper_bound(range);
		if (iter.equals( tree.begin() ) ) {
			return null;
		}
		iter.decrement();
		if ( !iter.get().getSpace().equals( spaceid ) ) {
			return null;
		}
		return iter.get();
	}

	public void printBounds( PrintStream s ) {
		if ( tree.isEmpty() ) {
			s.println( "all" );
		} else {
			IteratorSTL<Range> it;
			for ( it = tree.begin(); !it.isEnd(); it.increment() ) {
				Range range = it.get();
				range.printBounds( s );
			}
		}
	}

	public void saveXml( PrintStream s ) {
		s.println( "<rangelist>" );
		IteratorSTL<Range> it;
		for ( it = tree.begin(); !it.isEnd(); it.increment() ) {
			Range range = it.get();
			range.saveXml( s );
		}
		s.println( "</rangelist>" );
	}

	public void restoreXml( Element el, Translate trans ) {
		List<?> children = el.getChildren();
		for ( Object object : children ) {
			Element child = (Element) object;
			Range range = new Range();
			range.restoreXml( child, trans );
			tree.insert( range );
		}
	}

}
