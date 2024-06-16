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
/// \file rangemap.hh
/// \brief Templates to define interval map containers

#ifndef __RANGEMAP_HH__
#define __RANGEMAP_HH__

#include <set>
#include <list>

namespace ghidra {

/// \brief An interval map container
///
/// A container for records occupying (possibly overlapping)
/// intervals.  I.e. a map from a linear ordered domain to
/// (multiple) records.
/// The \b recordtype is the main object in the container, it must support:
///    - recordtype(inittype,linetype,linetype)   a constructor taking 3 parameters
///    - getFirst()     beginning of range
///    - getLast()      end of range (inclusive)
///    - getSubsort()   retrieve the subsorttype object (see below)
///
/// The \b recordtype must define data-types:
///    - linetype
///    - subsorttype
///    - inittype
///
/// \b linetype is the data-type of elements in the linear domain. It
/// must support:
///    - <,<=            Comparisons
///    - ==,!=           Equality
///    - + \<constant>   Addition of integers
///    - - \<constant>   Subtraction of integers
///
/// \b subsorttype describes how overlapping intervals can be sub-sorted. It
/// must support:
///    - <
///    - subsorttype(\b false)  constructor with \b false produces a minimal value
///    - subsorttype(\b true)   constructor with \b true produces a maximal value
///    - copy constructor
///
/// \b inittype is extra initialization data for the \b recordtype
///
/// The main interval map is implemented as a \e multiset of disjoint sub-ranges mapping
/// to the \b recordtype objects. After deduping the sub-ranges form the common refinement
/// of all the possibly overlapping \b recordtype ranges.  A sub-range is duplicated for each
/// distinct \b recordtype that overlaps that sub-range.  The sub-range multiset is updated
/// with every insertion or deletion of \b recordtype objects into the container, which
/// may insert new or delete existing boundary points separating the disjoint subranges.
template<typename _recordtype>
class rangemap {
public:
  typedef typename _recordtype::linetype linetype;	///< Integer data-type defining the linear domain
  typedef typename _recordtype::subsorttype subsorttype;	///< The data-type used for subsorting
  typedef typename _recordtype::inittype inittype;	///< The data-type containing initialization data for records
private:
  /// \brief The internal \e sub-range object for the interval map
  ///
  /// It defines a disjoint range within the common refinement of all ranges
  /// in the container. It also knows about its containing range and \b recordtype.
  class AddrRange {
    friend class rangemap<_recordtype>;
    friend class PartIterator;
    mutable linetype first;	///< Start of the disjoint sub-range
    linetype last;		///< End of the disjoint sub-range
    mutable linetype a;		///< Start of full range occupied by the entire \b recordtype
    mutable linetype b;		///< End of full range occupied by the entire \b recordtype
    mutable subsorttype subsort;	///< How \b this should be sub-sorted
    mutable typename std::list<_recordtype>::iterator value;	///< Iterator pointing at the actual \b recordtype
    AddrRange(linetype l) : subsort(false) { last = l; }	///< (Partial) constructor
    AddrRange(linetype l,const subsorttype &s) : subsort(s) { last = l; }	///< (Partial) constructor given a subsort
  public:
    bool operator<(const AddrRange &op2) const {
      if (last != op2.last) return (last < op2.last);
      return (subsort < op2.subsort);
    }	///< Comparison method based on ending boundary point
    typename std::list<_recordtype>::iterator getValue(void) const { return value; }	///< Retrieve the \b recordtype
  };
public:
  /// \brief An iterator into the interval map container
  ///
  /// This is really an iterator to the underlying multiset, but dereferencing it returns the
  /// \b recordtype.  Iteration occurs over the disjoint sub-ranges, thus the same \b recordtype
  /// may be visited multiple times by the iterator, depending on how much it overlaps other
  /// \b recordtypes. The sub-ranges are sorted in linear order, then depending on the \b subsorttype.
  class PartIterator {
    typename std::multiset<AddrRange>::const_iterator iter;	///< The underlying multiset iterator
  public:
    PartIterator(void) {}		///< Constructor
    PartIterator(typename std::multiset<AddrRange>::const_iterator i) { iter=i; }	///< Construct given iterator
    _recordtype &operator*(void) { return *(*iter).value; }	///< Dereference to the \b recordtype object
    PartIterator &operator++(void) { ++iter; return *this; }	///< Pre-increment the iterator
    PartIterator operator++(int i) {
      PartIterator orig(iter); ++iter; return orig; }		///< Post-increment the iterator
    PartIterator &operator--(void) { --iter; return *this; }	///< Pre-decrement the iterator
    PartIterator operator--(int i) {
      PartIterator orig(iter); --iter; return orig; }		///< Post-decrement the iterator
    PartIterator &operator=(const PartIterator &op2) {
      iter = op2.iter; return *this;
    }								///< Assign to the iterator
    bool operator==(const PartIterator &op2) const {
      return (iter==op2.iter);
    }								///< Test equality of iterators
    bool operator!=(const PartIterator &op2) const {
      return (iter!=op2.iter);
    }								///< Test inequality of iterators
    typename std::list<_recordtype>::iterator getValueIter(void) const {
      return (*iter).getValue(); }				///< Get the \b recordtype iterator
  };

  typedef PartIterator const_iterator;		///< The main sub-range iterator data-type

private:
  std::multiset<AddrRange> tree;	///< The underlying multiset of sub-ranges
  std::list<_recordtype> record;	///< Storage for the actual record objects

  void zip(linetype i,typename std::multiset<AddrRange>::iterator iter);	///< Remove the given partition boundary
  void unzip(linetype i,typename std::multiset<AddrRange>::iterator iter);	///< Insert the given partition boundary
public:
  bool empty(void) const { return record.empty(); }		///< Return \b true if the container is empty
  void clear(void) { tree.clear(); record.clear(); }		///< Clear all records from the container
  typename std::list<_recordtype>::const_iterator begin_list(void) const { return record.begin(); }	///< Beginning of records
  typename std::list<_recordtype>::const_iterator end_list(void) const { return record.end(); }	///< End of records
  typename std::list<_recordtype>::iterator begin_list(void) { return record.begin(); }	///< Beginning of records
  typename std::list<_recordtype>::iterator end_list(void) { return record.end(); }	///< End of records

  const_iterator begin(void) const { return PartIterator(tree.begin()); }	///< Beginning of sub-ranges
  const_iterator end(void) const { return PartIterator(tree.end()); }		///< Ending of sub-ranges

  /// \brief Find sub-ranges intersecting the given boundary point
  std::pair<const_iterator,const_iterator> find(linetype a) const;

  /// \brief Find sub-ranges intersecting given boundary point, and between given \e subsorts
  std::pair<const_iterator,const_iterator>
  find(linetype a,const subsorttype &subsort1,const subsorttype &subsort2) const;

  /// \brief Find beginning of sub-ranges that contain the given boundary point
  const_iterator find_begin(linetype point) const;

  /// \brief Find ending of sub-ranges that contain the given boundary point
  const_iterator find_end(linetype point) const;

  /// \brief Find first record overlapping given interval
  const_iterator find_overlap(linetype point,linetype end) const;

  /// \brief Insert a new record into the container
  typename std::list<_recordtype>::iterator insert(const inittype &data,linetype a,linetype b);

  /// \brief Erase a given record from the container
  void erase(typename std::list<_recordtype>::iterator v);

  /// \brief Erase a record given an iterator
  void erase(const_iterator iter) { erase( iter.getValueIter() ); }
};

/// All sub-ranges that end with the given boundary point are deleted, and all sub-ranges
/// that begin with the given boundary point (+1) are extended to cover the deleted sub-range.
/// This should run in O(k).
/// \param i is the given boundary point
/// \param iter points to the first sub-range that ends with the given boundary point
template<typename _recordtype>
void rangemap<_recordtype>::zip(linetype i,typename std::multiset<AddrRange>::iterator iter)

{
  linetype f = (*iter).first;
  while((*iter).last == i)
    tree.erase(iter++);
  i = i+1;
  while((iter!=tree.end())&&((*iter).first==i)) {
    (*iter).first = f;
    ++iter;
  }
}

/// All sub-ranges that contain the boundary point will be split into a sub-range
/// that ends at the boundary point and a sub-range that begins with the boundary point (+1).
/// This should run in O(k), where k is the number of intervals intersecting the boundary point.
/// \param i is the given boundary point
/// \param iter points to the first sub-range containing the boundary point
template<typename _recordtype>
void rangemap<_recordtype>::unzip(linetype i,typename std::multiset<AddrRange>::iterator iter)

{
  typename std::multiset<AddrRange>::iterator hint = iter;
  if ((*iter).last == i) return; // Can't split size 1 (i.e. split already present)
  linetype f;
  linetype plus1 = i+1;
  while((iter!=tree.end())&&((*iter).first<=i)) {
    f = (*iter).first;
    (*iter).first = plus1;
    typename std::multiset<AddrRange>::iterator newiter;
    newiter = tree.insert(hint,AddrRange(i,(*iter).subsort));
    const AddrRange &newrange( *newiter );
    newrange.first = f;
    newrange.a = (*iter).a;
    newrange.b = (*iter).b;
    newrange.value = (*iter).value;
    ++iter;
  }
}

/// \param data is other initialization data for the new record
/// \param a is the start of the range occupied by the new record
/// \param b is the (inclusive) end of the range
/// \return an iterator to the new record
template<typename _recordtype>
typename std::list<_recordtype>::iterator
rangemap<_recordtype>::insert(const inittype &data,linetype a,linetype b)

{
  linetype f=a;
  typename std::list<_recordtype>::iterator liter;
  typename std::multiset<AddrRange>::iterator low = tree.lower_bound(AddrRange(f));

  if (low != tree.end()) {
    if ((*low).first < f)	// Check if left boundary refines existing partition
      unzip(f-1,low);		// If so do the refinement
  }

  record.emplace_front( data, a, b );
  liter = record.begin();

  AddrRange addrrange(b,(*liter).getSubsort());
  addrrange.a = a;
  addrrange.b = b;
  addrrange.value = liter;
  typename std::multiset<AddrRange>::iterator spot = tree.lower_bound(addrrange);
  // Where does the new record go in full list, insert it
  record.splice( (spot==tree.end()) ? record.end():(*spot).value,
		 record,liter);

  while((low != tree.end())&&((*low).first<=b)) {
    if (f <= (*low).last) {	// Do we overlap at all
      if (f < (*low).first) {
	// Assume the hint makes this insert an O(1) op
	addrrange.first = f;
	addrrange.last = (*low).first-1;
	tree.insert(low,addrrange);
	f = (*low).first;
      }
      if ((*low).last <= b) {	// Insert as much of interval as we can
	addrrange.first = f;
	addrrange.last = (*low).last;
	tree.insert(low,addrrange);
	if ((*low).last==b) break; // Did we manage to insert it all
	f = (*low).last + 1;
      }
      else if (b < (*low).last) { // We can insert everything left, but must refine
	unzip(b,low);
	break;
      }
    }
    ++low;
  }
  if (f <= b) {
    addrrange.first = f;
    addrrange.last = b;
    tree.insert(addrrange);
  }

  return liter;
}

/// \param v is the iterator to the record to be erased
template<typename _recordtype>
void rangemap<_recordtype>::erase(typename std::list<_recordtype>::iterator v)

{
  linetype a = (*v).getFirst();
  linetype b = (*v).getLast();
  bool leftsew = true;
  bool rightsew = true;
  bool rightoverlap = false;
  bool leftoverlap = false;
  typename std::multiset<AddrRange>::iterator low = tree.lower_bound(AddrRange(a));
  typename std::multiset<AddrRange>::iterator uplow = low;

  linetype aminus1 = a-1;
  while (uplow != tree.begin()) {
    --uplow;
    if ((*uplow).last != aminus1) break;
    if ((*uplow).b == aminus1) {
      leftsew = false;		// Still a split between a-1 and a
      break;
    }
  }
  do {
    if ((*low).value == v)
      tree.erase(low++);
    else {
      if ((*low).a < a)
	leftoverlap = true;	// a splits somebody else
      else if ((*low).a == a)
	leftsew = false;	// Somebody else splits at a (in addition to v)
      if (b < (*low).b)
	rightoverlap = true;	// b splits somebody else
      else if ((*low).b == b)
	rightsew = false;	// Somebody else splits at b (in addition to v)
      low++;
    }
  } while ((low != tree.end())&&((*low).first<=b));
  if (low != tree.end()) {
    if ((*low).a-1 == b)
      rightsew = false;
  }
  if (leftsew&&leftoverlap)
    zip(a-1,tree.lower_bound(AddrRange(a-1)));
  if (rightsew&&rightoverlap)
    zip(b,tree.lower_bound(AddrRange(b)));
  record.erase(v);
}

/// \param point is the given boundary point
/// \return begin/end iterators over all intersecting sub-ranges
template<typename _recordtype>
std::pair<typename rangemap<_recordtype>::const_iterator,typename rangemap<_recordtype>::const_iterator>
rangemap<_recordtype>::find(linetype point) const

{
  AddrRange addrrange(point);
  typename std::multiset<AddrRange>::const_iterator iter1,iter2;

  iter1 = tree.lower_bound(addrrange);
  // Check for no intersection
  if ((iter1==tree.end())||(point < (*iter1).first))
    return std::pair<PartIterator,PartIterator>(PartIterator(iter1),PartIterator(iter1));

  AddrRange addrend((*iter1).last,subsorttype(true));
  iter2 = tree.upper_bound(addrend);
    
  return std::pair<PartIterator,PartIterator>(PartIterator(iter1),PartIterator(iter2));
}

/// \param point is the given boundary point
/// \param sub1 is the starting subsort
/// \param sub2 is the ending subsort
/// \return begin/end iterators over all intersecting and bounded sub-ranges
template<typename _recordtype>
std::pair<typename rangemap<_recordtype>::const_iterator,typename rangemap<_recordtype>::const_iterator>
rangemap<_recordtype>::find(linetype point,const subsorttype &sub1,const subsorttype &sub2) const

{
  AddrRange addrrange(point,sub1);
  typename std::multiset<AddrRange>::const_iterator iter1,iter2;

  iter1 = tree.lower_bound(addrrange);
  if ((iter1==tree.end())||(point < (*iter1).first))
    return std::pair<PartIterator,PartIterator>(PartIterator(iter1),PartIterator(iter1));
  
  AddrRange addrend((*iter1).last,sub2);
  iter2 = tree.upper_bound(addrend);

  return std::pair<PartIterator,PartIterator>(PartIterator(iter1),PartIterator(iter2));
}

/// \param point is the given boundary point
/// \return iterator to first sub-range of intersects the boundary point
template<typename _recordtype>
typename rangemap<_recordtype>::const_iterator
rangemap<_recordtype>::find_begin(linetype point) const

{
  AddrRange addrrange(point);
  typename std::multiset<AddrRange>::const_iterator iter;

  iter = tree.lower_bound(addrrange);
  return iter;
}

/// \param point is the given boundary point
/// \return iterator to first sub-range after that does not intersect the boundary point
template<typename _recordtype>
typename rangemap<_recordtype>::const_iterator
rangemap<_recordtype>::find_end(linetype point) const

{
  AddrRange addrend(point,subsorttype(true));
  typename std::multiset<AddrRange>::const_iterator iter;

  iter = tree.upper_bound(addrend);
  if ((iter==tree.end())||(point < (*iter).first))
    return iter;

  // If we reach here, (*iter).last is bigger than point (as per upper_bound) but
  // point >= than (*iter).first, i.e. point is contained in the sub-range.
  // So we have to do one more search for first sub-range after the containing sub-range.
  AddrRange addrbeyond((*iter).last,subsorttype(true));
  return tree.upper_bound(addrbeyond);
}

/// \param point is the start of interval to test
/// \param end is the end of the interval to test
/// \return iterator to first sub-range of an intersecting record (or \b end)
template<typename _recordtype>
typename rangemap<_recordtype>::const_iterator
rangemap<_recordtype>::find_overlap(linetype point,linetype end) const

{
  AddrRange addrrange(point);
  typename std::multiset<AddrRange>::const_iterator iter;

  // First range where right boundary is equal to or past point
  iter = tree.lower_bound(addrrange);
  if (iter==tree.end()) return iter;
  if ((*iter).first<=end)
    return iter;
  return tree.end();
}

} // End namespace ghidra
#endif
