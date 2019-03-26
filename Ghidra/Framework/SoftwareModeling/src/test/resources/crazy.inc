print $(FOO)
@define FOO bar
@include "empty.input"
print $(FOO) again
@undef FOO
