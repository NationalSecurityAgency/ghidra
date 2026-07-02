#
# Register $@ unit files with systemd service.
#
register_services ()
{
  for unit in "$@"; do
    systemctl enable --now "$unit"
  done
}


#
# Unregister $@ unit files with systemd service.
#
unregister_services ()
{
  for unit in "$@"; do
    if file_belongs_to_single_package "$unit"; then
      local unit_name=`basename "$unit"`
      if systemctl list-units --full -all | grep -q "$unit_name"; then
        systemctl disable --now "$unit_name"
      fi
    fi
  done
}

file_belongs_to_single_package ()
{
  if [ ! -e "$1" ]; then
    false
  elif [ "$package_type" = rpm ]; then
    test `rpm -q --whatprovides "$1" | wc -l` = 1
  elif [ "$package_type" = deb ]; then
    test `dpkg -S "$1" | wc -l` = 1
  else
    exit 1
  fi
}
