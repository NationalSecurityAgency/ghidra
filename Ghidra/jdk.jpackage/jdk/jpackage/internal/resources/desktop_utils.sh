#
# Remove $1 desktop file from the list of default handlers for $2 mime type
# in $3 file dumping output to stdout.
#
_filter_out_default_mime_handler ()
{
  local defaults_list="$3"

  local desktop_file="$1"
  local mime_type="$2"

  awk -f- "$defaults_list" <<EOF
  BEGIN {
    mime_type="$mime_type"
    mime_type_regexp="~" mime_type "="
    desktop_file="$desktop_file"
  }
  \$0 ~ mime_type {
    \$0 = substr(\$0, length(mime_type) + 2);
    split(\$0, desktop_files, ";")
    remaining_desktop_files
    counter=0
    for (idx in desktop_files) {
      if (desktop_files[idx] != desktop_file) {
        ++counter;
      }
    }
    if (counter) {
      printf mime_type "="
      for (idx in desktop_files) {
        if (desktop_files[idx] != desktop_file) {
          printf desktop_files[idx]
          if (--counter) {
            printf ";"
          }
        }
      }
      printf "\n"
    }
    next
  }

  { print }
EOF
}


#
# Remove $2 desktop file from the list of default handlers for $@ mime types
# in $1 file.
# Result is saved in $1 file.
#
_uninstall_default_mime_handler ()
{
  local defaults_list=$1
  shift
  [ -f "$defaults_list" ] || return 0

  local desktop_file="$1"
  shift

  tmpfile1=$(mktemp)
  tmpfile2=$(mktemp)
  cat "$defaults_list" > "$tmpfile1"

  local v
  local update=
  for mime in "$@"; do
    _filter_out_default_mime_handler "$desktop_file" "$mime" "$tmpfile1" > "$tmpfile2"
    v="$tmpfile2"
    tmpfile2="$tmpfile1"
    tmpfile1="$v"

    if ! diff -q "$tmpfile1" "$tmpfile2" > /dev/null; then
      update=yes
      trace Remove $desktop_file default handler for $mime mime type from $defaults_list file
    fi
  done

  if [ -n "$update" ]; then
    cat "$tmpfile1" > "$defaults_list"
    trace "$defaults_list" file updated
  fi

  rm -f "$tmpfile1" "$tmpfile2"
}


#
# Remove $1 desktop file from the list of default handlers for $@ mime types
# in all known system defaults lists.
#
uninstall_default_mime_handler ()
{
  for f in /usr/share/applications/defaults.list /usr/local/share/applications/defaults.list; do
    _uninstall_default_mime_handler "$f" "$@"
  done
}


trace ()
{
  echo "$@"
}
