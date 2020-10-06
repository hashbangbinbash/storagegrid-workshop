#! /bin/bash
#
# Copyright (C) 2015-2019 NetApp, Inc., All Rights Reserved
#
# Script to deploy StorageGRID software onto virtual machines.
#
# Overview:
#   This script needs to be run on *NIX machine.
#   Prerequisite: VMware ovftool version 4.1.0.
#   Download ovftool from www.vmware.com
#
#   Start with the sample configuration file and modify it for your deployment.
#
#   Exit status:
#   0 - All nodes deployed successfully
#   1 - All nodes deployed but there were some errors, review the output
#   2 - There were failed deployments, review the output
#   3 - There were unknown results, review the output
#   4 - There was no status file (ovftool was not executed)
#   5 - Could not execute this script... Input error.
#

# Global variables
LF=$'\n'
MAX_JOBS=5
MAX_RETRIES=2
IFS_ORIG=$IFS
PING_IPS=()

RELEASE_VERSION=11.4.0

ARCHIVE_FILE=vsphere-archive
GATEWAY_FILE=vsphere-gateway
NON_PRIMARY_FILE=vsphere-non-primary-admin
PRIMARY_FILE=vsphere-primary-admin
STORAGE_FILE=vsphere-storage

DEFAULT_SOURCE=$(echo $(cd $(dirname $0); pwd))

# Apply set -x as soon as possible if specified (during argument parsing is too late)
for arg in "$@" ; do
  if [[ $arg == '-x' ]] ; then
    echo "Enabling bash set -x mode"
    set -x
    break
  fi
done

# Check for BASH 4.X
read -r MAJ MIN <<< $(echo $BASH_VERSION| sed 's/[^0-9\.]*//g'| awk -F. '{print $1" "$2}')
if ! ([[ $MAJ -ge 4 ]] || ([[ $MAJ -eq 3 ]] && [[ $MIN -ge 2 ]])); then
  echo "Warning: $(basename $0) was developed for bash versions 3.2 and newer." >&2
  echo "You seem to be using an older version of bash; if you experience issues with your deployment," >&2
  echo "try running $(basename $0) on a system equipped with bash version 3.2 or newer." >&2
fi

# Check for ovftool
OVFTOOL=$(which ovftool)
if [[ $OVFTOOL == '' ]]; then
  echo 'Could not find "ovftool"; Please download it from www.vmware.com.' >&2
  exit 5
else
  # Get and parse ovftool version
  read -r MAJ MIN <<< $($OVFTOOL -v| awk '{print $3}'| awk -F. '{print $1" "$2}')

  # Check for minimum of 4.1
  if [[ $MAJ -lt 4 ]] || ([[ $MAJ -eq 4 ]] && [[ $MIN -lt 1 ]]); then
    echo "Warning: The $(basename $0) script was developed with VMware ovftool version 4.1.0." >&2
    echo "You seem to be using an older version of ovftool; if you experience issues with your deployment," >&2
    echo "consider upgrading to the latest version."
  fi
fi

function usage
{
  echo
  echo -e 'Usage:\n'
  echo "  $(basename $0) [OPTIONS] <config-file>"
  echo
  echo '  Where:'
  echo '  <config-file>       - Configuration file for' $(basename $0)
  echo '                        See deploy-vsphere-ovftool.sample.ini as an example'
  echo
  echo '  OPTIONS:'
  echo '  -b/--background     - Run ovftool in background (parallel deployments)'
  echo '                        NOTE: --powerOn option may fail if deploying into vApps'
  echo '  -d/--debug          - Shows more detals in steps/variables'
  echo '  -D/--do-not-delete  - Leaves behind directories in /tmp/'
  echo '  -h/--help           - This output'
  echo '  -I/--ignore-ping    - Bypasses pinging of all hosts.'
  echo '  -i/--interactive=once|all'
  echo '                      - Ignore all username/password values in the <config-file>'
  echo '                        Provide username and password interactively'
  echo '                        once - Prompts a single time'
  echo '                        all  - Prompts for each ovftool call'
  echo '  -j/--jobs=<#>       - Used in conjunction with -b to specify the maximum'
  echo '                        number of background instances of ovftool'
  echo '                        Defaults to 5'
  echo '  -n/--no-op          - Skips call(s) to "ovftool"'
  echo '                        Also shows the ovftool command line with arguments.'
  echo '  -p/--password=<password>'
  echo '                      - For automation purposes'
  echo '                        Provide password on the command-line'
  echo '                        Override password(s) in the <config-file>'
  echo '                        NOTE: Insecure as password is visible via "ps" command'
  echo '  -r/--retries=<#>    - Specifies the number of retries to deploy each node'
  echo '                        Defaults to 2 (in addition to initial attempt)'
  echo '  -S/--single-node=<section-name>'
  echo '                      - Deploy a single node by specifying the section name.'
  echo '  -s/--source=<ovf-dir>'
  echo '                      - Specify directory or URL of directory containing ovf files'
  echo '                        Override source in the <config-file>'
  echo "                        Defaults to $DEFAULT_SOURCE"
  echo '  -t/--target=<vCenter-target>'
  echo '                      - Specify target URL (vi://<server>)'
  echo '                        Override target(s) in the <config-file>'
  echo '  -u/--username=<username>'
  echo '                      - For automation purposes'
  echo '                        Provide username on the command-line'
  echo '                        Override username(s) in the <config-file>'
  echo '  -m/--memory=<#>     - Override memory size (in GB) allocated to each server'
  echo '  -e/--memory-reservation=<#>'
  echo '                      - Override memory reservation (in GB) allocated to each server'
  echo '                        NOTE: This option should not be used for production deployments'
  echo '  -c/--cores=<#>      - Override number of cpu cores allocated to each server'
  echo '  -x                  - Sets "-x" in bash (for debugging)'
  echo '                        NOTE: May expose password(s) in output'

  exit 5
}

function validate_ini_format
{
  local CONFIG_FILE=$1
  local LINE_NO=0
  local LINE=
  local SECTION='GLOBALS'
  local KEY=
  local VALUE=

  # Iterate over the config-file
  while read -r LINE; do
    let LINE_NO++

    # Reformat LINE:
    # - Add spaces around the first equal
    # - Remove tabs
    # - Remove CR (^M) DOS format
    LINE=${LINE/=/ = }
    LINE=${LINE//$'\t'/ }
    LINE=${LINE//$'\015'/}

    # Check if line is blank or a comment
    if [[ $LINE == '' ]] || [[ ${LINE:0:1} =~ ['#;'] ]]; then
      continue
    # Check for a section divider
    elif [[ ${LINE:0:1} == '[' ]];then
      if [[ ${LINE:$[${#LINE}-1]:1} != ']' ]];then
        echo "Error: Line $LINE_NO: ($LINE) Invalid section delimiter, expecting \"[Section]\"" >&2
        exit 5
      else
        SECTION=$(echo "$LINE"| sed -e "s/\s*\[\s*//g" -e "s/\s*\]\s*//g")
        continue
      fi
    else
      # Parse the line ( This should be "KEY = VALUE")
      KEY=${LINE%%=*}
      VALUE=${LINE#*=}
      # Remove leading / trailing space
      KEY="${KEY#"${KEY%%[![:space:]]*}"}"
      KEY="${KEY%"${KEY##*[![:space:]]}"}"
      VALUE="${VALUE#"${VALUE%%[![:space:]]*}"}"
      VALUE="${VALUE%"${VALUE##*[![:space:]]}"}"
      if ! [[ $LINE =~ '=' ]]; then
        echo "Error: Line $LINE_NO: ($LINE) Did not find equal sign, expecting \"KEY = VALUE\"" >&2
        exit 5
      elif [[ $KEY =~ ^[A-Z_]*$ ]]; then
        # Just checking individual key values
        instantiate_vars "$KEY=$VALUE" "$SECTION" "$LINE_NO"
        continue
      else
        echo "Error: Line $LINE_NO: ($LINE) Invalid characters in KEY" >&2
        exit 5
      fi
    fi
  done < "$CONFIG_FILE"
}

function validate_node_name
{
  local NODE_NAME=$1

  if [[ ! $NODE_NAME =~ ^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$ ]]; then
    echo "Error: Node name '$NODE_NAME' is not a valid hostname. Must consist of only letters, digits or hyphens, section ($SECTION_NAME)" >&2
    exit 5
  fi
}

function ip2dec
{
  local A B C D IP=$1
  local IFS=.
  read -r A B C D <<< "$IP"
  # Verify a valid IP
  if ! ([[ $A =~ ^[0-9]+$ ]] && [[ $B =~ ^[0-9]+$ ]] && [[ $C =~ ^[0-9]+$ ]] && [[ $D =~ ^[0-9]+$ ]] &&
        [[ $A -lt 256 ]] && [[ $B -lt 256 ]] && [[ $C -lt 256 ]] && [[ $D -lt 256 ]]); then
    return
  fi
  # Convert to decimal
  echo "$((A * 256 ** 3 + B * 256 ** 2 + C * 256 + D))"
}

function ping_ips
{
  echo "${LF}Pinging hosts in background..."
  local I=0
  local PING_IPS=("$@")

  while [[ $I -lt ${#PING_IPS[@]} ]]; do
    # Single ping, dispose of output and run in background
    ping -c 1 ${PING_IPS[$I]} >/dev/null 2>&1 &
    let I++
  done

  I=0
  while [[ $I -lt ${#PING_IPS[@]} ]]; do
    wait %$((I+1))
    if [[ $? -eq 0 ]]; then
      echo "Host: ${PING_IPS[$I]} has responded to ping!"
      EXIT_STATUS=5
    fi
    let I++
  done

  if [[ $EXIT_STATUS ]]; then
    echo "${LF}Some of the IP addresses you've provided appear to be in use." >&2
    echo "If you are certain it is safe to do so, you can force the grid deployment" >&2
    echo "to proceed anyway by specifying the \"--ignore-ping\" option." >&2
    exit $EXIT_STATUS
  fi
}

function validate_net
{
  local TARGET=$1
  local CONFIG=$2
  local IP=$3
  local MASK=$4
  local GATEWAY=$5
  local SECTION_NAME=$6
  local LABEL=$7

  if [[ $CONFIG != 'DISABLED' ]] && [[ -z $TARGET ]]; then
    echo "Error: $LABEL network TARGET required when CONFIG != DISABLED, section ($SECTION_NAME)" >&2
    exit 5
  fi

  if [[ $CONFIG == 'DISABLED' ]]; then
    if [[ -n $IP ]]; then
      echo "Error: $LABEL network IP is not allowed when network CONFIG set to DISABLED, section ($SECTION_NAME):" >&2
      exit 5
    fi
  elif [[ $CONFIG == 'STATIC' ]]; then
    # Ensure these parameters are set:
    if [[ -z $MASK ]] || [[ -z $IP ]]; then
      echo "Error: Incomplete section ($SECTION_NAME):" >&2
      echo "Required when $LABEL network CONFIG == STATIC, $LABEL network IP MASK" >&2
      exit 5
    fi

    # Check for valid IP and MASK
    local IP_DEC=$(ip2dec $IP)
    if [[ -z $IP_DEC ]]; then
      echo "Error: Invalid $LABEL network IP ($IP)" >&2
      exit 5
    fi
    local MASK_DEC=$(ip2dec $MASK)
    if [[ -z $MASK_DEC ]]; then
      echo "Error: Invalid $LABEL network MASK ($MASK)" >&2
      exit 5
    fi

    # If GATEWAY is defined, check for valid format and that IP
    # and GATEWAY are in the same subnet
    if [[ -n $GATEWAY ]]; then
      local GATEWAY_DEC=$(ip2dec $GATEWAY)
      if [[ -z $GATEWAY_DEC ]]; then
        echo "Error: Invalid $LABEL network GATEWAY ($GATEWAY)" >&2
        exit 5
      fi

      local GATEWAY_NET=$(($GATEWAY_DEC & $MASK_DEC))
      local IP_NET=$(($IP_DEC & $MASK_DEC))
      if [[ $GATEWAY_NET -ne $IP_NET ]]; then
        echo "Error: $LABEL network GATEWAY and IP in section ($SECTION_NAME) are not in the same network." >&2
        echo "Check: $LABEL network GATEWAY ($GATEWAY), IP ($IP) and MASK ($MASK)" >&2
        exit 5
      fi
    fi

    # Check for duplicate IPs
    if [[ $IP == $(printf "%s\n" ${PING_IPS[@]}| grep "^$IP$") ]];then
      echo "Error: Duplicate $LABEL network IP ($IP) found in section ($SECTION_NAME)." >&2
      exit 5
    fi
    # Add IP to the array PING_IPS (we'll ping them later)
    PING_IPS+=($IP)
  fi
}

function instantiate_vars
{
  local VARS=$1
  local SECTION_NAME=$2
  local LINE=
  local LINE_NO=$3

  local ERROR=

  while read -r LINE; do
    # Parse the line ( This should be "KEY = VALUE")
    local KEY=${LINE%%=*}
    local VALUE=${LINE#*=}
    # Remove leading / trailing space
    KEY="${KEY#"${KEY%%[![:space:]]*}"}"
    KEY="${KEY%"${KEY##*[![:space:]]}"}"
    VALUE="${VALUE#"${VALUE%%[![:space:]]*}"}"
    VALUE="${VALUE%"${VALUE##*[![:space:]]}"}"

    local ERROR_PREFIX='Error:'
    [[ $LINE_NO ]] && ERROR_PREFIX="$ERROR_PREFIX Line $LINE_NO:"
    ERROR_PREFIX="$ERROR_PREFIX ($LINE)"

    if [[ $KEY != "SOURCE" ]] && [[ -z $VALUE ]]; then
      echo "$ERROR_PREFIX VALUE is unset; expected \"KEY = VALUE\"" >&2
      exit 5
    fi

    case "$KEY" in
      ADMIN_IP|GRID_NETWORK_GATEWAY|GRID_NETWORK_MASK|GRID_NETWORK_IP|\
      ADMIN_NETWORK_IP|ADMIN_NETWORK_MASK|ADMIN_NETWORK_GATEWAY|ADMIN_NETWORK_ESL|\
      CLIENT_NETWORK_IP|CLIENT_NETWORK_MASK|CLIENT_NETWORK_GATEWAY)
        PROP_VARS="$PROP_VARS --prop:$KEY='$VALUE'"
        # Instantiate these for further verification (below)
        eval "$KEY='$VALUE'"
        ;;
      GRID_NETWORK_TARGET|ADMIN_NETWORK_TARGET|CLIENT_NETWORK_TARGET|NODE_NAME)
        eval "$KEY='$VALUE'"
        ;;
      GRID_NETWORK_MTU|ADMIN_NETWORK_MTU|CLIENT_NETWORK_MTU)
        if [[ $VALUE != ${VALUE//[^[:digit:]]} ]] || [[ $VALUE -lt 68 ]] || [[ $VALUE -gt 65535 ]]; then
          ERROR="Invalid $KEY ($VALUE), must be value between 68 and 65535"
        fi
        UPDATE_MTU=1
        eval "$KEY='$VALUE'"
        ;;
      DEV) # Ignore, but should really go away.
        ;;
      MEMORY_GB)
        MEMORY_GB="$VALUE"
        ;;
      MEMORY_RESERVATION_GB)
        MEMORY_RESERVATION_GB="$VALUE"
        ;;
      CORES)
        CORES="$VALUE"
        ;;
      DISK)
        DISK_VARS="$DISK_VARS$LF$VALUE"
        ;;
      ADMIN_ROLE)
        if ! [[ $VALUE =~ ^(Primary|Non-Primary)$ ]]; then
          ERROR="Invalid ADMIN_ROLE ($VALUE); expected one of: \"Primary\", \"Non-Primary\""
        fi
        ADMIN_ROLE=$VALUE
        ;;
      GRID_NETWORK_CONFIG)
        if ! [[ $VALUE =~ ^(DHCP|STATIC)$ ]]; then
          ERROR="Invalid $KEY ($VALUE); expected one of: \"DHCP\", \"STATIC\""
        fi
        eval "$KEY='$VALUE'"
        ;;
      ADMIN_NETWORK_CONFIG|CLIENT_NETWORK_CONFIG)
        if ! [[ $VALUE =~ ^(DISABLED|DHCP|STATIC)$ ]]; then
          ERROR="Invalid $KEY ($VALUE); expected one of: \"DISABLED\", \"DHCP\", \"STATIC\""
        fi
        eval "$KEY='$VALUE'"
        ;;
      NODE_TYPE)
        if ! [[ $VALUE =~ ^(VM_Storage_Node|VM_Admin_Node|VM_API_Gateway|VM_Archive_Node)$ ]]; then
          ERROR="Invalid NODE_TYPE ($VALUE); expected one of: "
          ERROR="$ERROR\"VM_Storage_Node\", \"VM_Admin_Node\", \"VM_API_Gateway\" or \"VM_Archive_Node\""
        fi
        NODE_TYPE=$VALUE
        ;;
      OVFTOOL_ARGUMENTS)
        OVFTOOL_ARGUMENTS=$VALUE
        ;;
      PASSWORD)
        PASSWORD=$VALUE
        ;;
      RUN_ON_SUCCESS)
        RUN_ON_SUCCESS=$VALUE
        ;;
      SOURCE)
        SOURCE=$VALUE
        ;;
      TARGET)
        TARGET=$VALUE
        ;;
      USERNAME)
        USERNAME=$VALUE
        ;;
      *)
        echo "$ERROR_PREFIX Unknown KEY ($KEY)" >&2
        exit 5
      ;;
    esac
    if [[ $ERROR ]]; then
      echo "$ERROR_PREFIX $ERROR" >&2
      exit 5
    fi
  done <<< "$VARS"

  # If there was a line number, an individual parameter was checked (above)
  [[ $LINE_NO ]] && return 0

  if [[ -z $NODE_TYPE ]] || [[ -z $GRID_NETWORK_TARGET ]]; then
    echo "Error: Incomplete section ($SECTION_NAME):" >&2
    echo "Required: NODE_TYPE, GRID_NETWORK_TARGET" >&2
    exit 5
  fi
  NET_VARS="$NET_VARS --net:'Grid Network'='$GRID_NETWORK_TARGET'"

  if [[ $NODE_TYPE == 'VM_Admin_Node' ]] && [[ -z $ADMIN_ROLE ]]; then
   echo "Error: Incomplete section ($SECTION_NAME):" >&2
   echo "Required when NODE_TYPE = \"VM_Admin_Node\": ADMIN_ROLE={Primary|Non-Primary}" >&2
   exit 5
  fi

  if [[ $ADMIN_ROLE == 'Primary' ]]; then
    if [[ $PRIMARY_ADMIN_SEEN == 1 ]]; then
      echo "Error: Multiple Primary Admin nodes, section ($SECTION_NAME):" >&2
      echo "A grid may only contain a single Primary admin node" >&2
      exit 5
    else
      PRIMARY_ADMIN_SEEN=1
    fi
  fi

  # Make GRID_NETWORK_CONFIG default to STATIC if needed
  if [[ -z $GRID_NETWORK_CONFIG ]]; then
    GRID_NETWORK_CONFIG='STATIC'
  fi
  PROP_VARS="$PROP_VARS --prop:GRID_NETWORK_CONFIG='$GRID_NETWORK_CONFIG'"

  # Optional networks default to DHCP
  if [[ -z $ADMIN_NETWORK_CONFIG ]]; then
    ADMIN_NETWORK_CONFIG='DISABLED'
  fi
  PROP_VARS="$PROP_VARS --prop:ADMIN_NETWORK_CONFIG='$ADMIN_NETWORK_CONFIG'"

  if [[ -z $CLIENT_NETWORK_CONFIG ]]; then
    CLIENT_NETWORK_CONFIG='DISABLED'
  fi
  PROP_VARS="$PROP_VARS --prop:CLIENT_NETWORK_CONFIG='$CLIENT_NETWORK_CONFIG'"

  if [[ -n $DISK_VARS ]]; then
    if [[ $NODE_TYPE != 'VM_Storage_Node' ]] && [[ $NODE_TYPE != 'VM_Admin_Node' ]]; then
      echo "Warning: DISK parameters ignored for node type '$NODE_TYPE', section ($SECTION_NAME)" >&2
      unset DISK_VARS
    fi
  fi

  validate_net "$GRID_NETWORK_TARGET" "$GRID_NETWORK_CONFIG" "$GRID_NETWORK_IP" "$GRID_NETWORK_MASK"\
               "$GRID_NETWORK_GATEWAY" "$SECTION_NAME" "grid"
  validate_net "$ADMIN_NETWORK_TARGET" "$ADMIN_NETWORK_CONFIG" "$ADMIN_NETWORK_IP" "$ADMIN_NETWORK_MASK"\
               "$ADMIN_NETWORK_GATEWAY" "$SECTION_NAME" "admin"
  validate_net "$CLIENT_NETWORK_TARGET" "$CLIENT_NETWORK_CONFIG" "$CLIENT_NETWORK_IP" "$CLIENT_NETWORK_MASK"\
               "$CLIENT_NETWORK_GATEWAY" "$SECTION_NAME" "client"

  # After network validation, default empty targets to grid network target
  if [[ -z $ADMIN_NETWORK_TARGET ]]; then
    ADMIN_NETWORK_TARGET=$GRID_NETWORK_TARGET
  fi
  NET_VARS="$NET_VARS --net:'Admin Network'='$ADMIN_NETWORK_TARGET'"

  if [[ -z $CLIENT_NETWORK_TARGET ]]; then
    CLIENT_NETWORK_TARGET=$GRID_NETWORK_TARGET
  fi
  NET_VARS="$NET_VARS --net:'Client Network'='$CLIENT_NETWORK_TARGET'"
}

# Modify WHOLE_BLOCK by adding unique variables from GLOBAL_BLOCK
function apply_globals_to_whole_block
{
  local GLOBALS=$1
  local LINE=
  local KEY=
  local VALUE=

  local IFS=$LF # Set field separator to LF
  for LINE in $GLOBALS; do
    IFS=$IFS_ORIG # Restore IFS
    # Parse the line ( This should be "KEY = VALUE")
    KEY=${LINE%%=*}
    VALUE=${LINE#*=}
    # Remove leading / trailing space
    KEY="${KEY#"${KEY%%[![:space:]]*}"}"
    KEY="${KEY%"${KEY##*[![:space:]]}"}"
    VALUE="${VALUE#"${VALUE%%[![:space:]]*}"}"
    VALUE="${VALUE%"${VALUE##*[![:space:]]}"}"

    # Add all DISK entries as well as unique entries
    if [[ $KEY == 'DISK' ]] || [[ $(echo "$WHOLE_BLOCK"| grep "^$KEY ") == '' ]]; then
      WHOLE_BLOCK="$WHOLE_BLOCK$LF$KEY=$VALUE"
    fi
  done
}

function find_vmdk_name
{
  local OVF_FILE=$1
  local VMDK_PATTERN='<File ovf:href="([^"]*)" ovf:id="sgroot-vmdk"'
  local VMDK_FILE=$(sed -n -r -e "s/.*${VMDK_PATTERN}.*/\1/p" $OVF_FILE)
  if [[ -z $VMDK_FILE ]]; then
    echo "Error: Can't find VMDK file name in OVF: $OVF_FILE" >&2
    exit 5
  fi
  echo $VMDK_FILE
}

# Updates SOURCE_CACHE, VMDK_FILE
function download_source {
  local SOURCE=$1

  which curl >/dev/null || ( echo "${LF}This script requires curl to download '$SOURCE'." \
                                      "${LF}Please install curl and try again." >&2 && exit 5 )
  # Get a list of all the OVFs at the source
  local OVF_PATTERN="vsphere-.*\.ovf"
  local OVF_FILES=$(curl -s ${SOURCE}/ | sed -n -r -e "s/.*($OVF_PATTERN).*/\1/p")
  if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    echo "Error: failed to download $SOURCE" >&2
    exit 5
  fi

  if [[ -z "$OVF_FILES" ]]; then
    echo "Error: No OVF files found at ${SOURCE} matching ${OVF_PATTERN}" >&2
    exit 5
  fi

  SOURCE_CACHE=$(mktemp -d --suffix=.dvo)
  # Track all the temporary dirs in an global array
  TMP_DIRS+=($SOURCE_CACHE)

  pushd $SOURCE_CACHE > /dev/null
    for OVF_FILE in $OVF_FILES; do
      local OVF_URL="$SOURCE/$OVF_FILE"
      echo "Downloading $OVF_URL"
      curl -O "$OVF_URL" || exit 5

      local MF_FILE=${OVF_FILE/.ovf/.mf}
      local MF_URL="$SOURCE/$MF_FILE"
      echo "Downloading $MF_URL"
      curl -O "${MF_URL}" || exit 5
    done
    VMDK_FILE=$(find_vmdk_name $OVF_FILE)
    local VMDK_URL="$SOURCE/$VMDK_FILE"
    echo "Downloading $VMDK_URL"
    curl -O "${VMDK_URL}" || exit 5
  popd > /dev/null
}

# Check ovf, vmdk and mf... If a URL was provided, fetch them
function verify_and_fetch_source
{
  local SOURCE=$1   # Directory or URL pointing to a directory
  local NODE_TYPE=$2
  local ADMIN_ROLE=$3

  local FILE_BASE
  case "$NODE_TYPE" in
    VM_Admin_Node)
      if [[ $ADMIN_ROLE == 'Primary' ]]; then
        FILE_BASE="$PRIMARY_FILE"
      else
        FILE_BASE="$NON_PRIMARY_FILE"
      fi
      ;;
    VM_Archive_Node)
      FILE_BASE="$ARCHIVE_FILE"
      ;;
    VM_API_Gateway)
      FILE_BASE="$GATEWAY_FILE"
      ;;
    VM_Storage_Node)
      FILE_BASE="$STORAGE_FILE"
      ;;
  esac

  # If we have a cache, use it
  if [[ -d $SOURCE_CACHE ]]; then
    OVF="$SOURCE_CACHE/${FILE_BASE}.ovf"
    VMDK_FILE=$(find_vmdk_name $OVF)
    MANIFEST="$SOURCE_CACHE/${FILE_BASE}.mf"
    VMDK="$SOURCE_CACHE/${VMDK_FILE}"
  else
    if [[ $SOURCE =~ 'http://' ]] || [[ $SOURCE =~ 'https://' ]]; then
      download_source "$SOURCE" # Updates SOURCE_CACHE, VMDK_FILE
      OVF="$SOURCE_CACHE/${FILE_BASE}.ovf"
      MANIFEST="$SOURCE_CACHE/${FILE_BASE}.mf"
      VMDK="$SOURCE_CACHE/${VMDK_FILE}"
    else
      OVF="$SOURCE/${FILE_BASE}.ovf"
      VMDK_FILE=$(find_vmdk_name $OVF)
      MANIFEST="$SOURCE/${FILE_BASE}.mf"
      VMDK="$SOURCE/${VMDK_FILE}"
    fi
  fi

  if [[ -f $OVF ]]; then
    if [[ ! -f $VMDK ]]; then
      echo "VMDK '$VMDK' not found" >&2
      exit 5
    fi
    if [[ ! -f $MANIFEST ]]; then
      echo "Error: Manifest '$MANIFEST' not found" >&2
      exit 5
    fi
  else
    echo "Error: OVF '$OVF' not found" >&2
    exit 5
  fi
}

function copy_source
{
  # Not local, updated to reflect tmp dir location
  OVF=$1
  local VMDK=$2
  local MANIFEST=$3

  local TMP_DIR=$(mktemp -d --suffix=.dvo)
  # Track all the temporary dirs in an global array
  TMP_DIRS+=($TMP_DIR)

  # Get the full path to the VMDK (resolve relative path)
  if [[ ! $VMDK =~ ^/ ]]; then
    echo "Warning: $VMDK is not absolute path" >&2
    VMDK="$PWD/$VMDK"
    echo "Using: $VMDK" >&2
  fi

  cp "$OVF" $TMP_DIR || exit 5
  cp "$MANIFEST" $TMP_DIR || exit 5

  # Update OVF to match this copy's location
  OVF="$TMP_DIR/$(basename $OVF)"

  # Override CPU and memory specifications if specified
  if [[ $CORES != '' ]]; then
    echo "$SECTION_NAME: setting CORES to $CORES"
    sed -i -e "s%<rasd:ElementName>8 virtual CPU(s)</rasd:ElementName>%<rasd:ElementName>${CORES} virtual CPU(s)</rasd:ElementName>%" \
        -e "s%<rasd:VirtualQuantity>8</rasd:VirtualQuantity>%<rasd:VirtualQuantity>${CORES}</rasd:VirtualQuantity>%" $OVF || exit 5
  fi
  if [[ ($MEMORY_GB != '') || ($MEMORY_RESERVATION_GB != '') ]]; then
    # Backwards-compatibility with old .ovfs (unit GB, reservation 4)
    sed -i -e "s%<rasd:AllocationUnits>byte \* 2^30</rasd:AllocationUnits>%<rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>%" \
        -e "s%<rasd:ElementName>24GB of memory</rasd:ElementName>%<rasd:ElementName>24576MB of memory</rasd:ElementName>%" \
        -e "s%<rasd:VirtualQuantity>24</rasd:VirtualQuantity>%<rasd:VirtualQuantity>24576</rasd:VirtualQuantity>%" \
        -e "s%<rasd:Reservation>4</rasd:Reservation>%<rasd:Reservation>24576</rasd:Reservation>%" $OVF || exit 5
  fi
  if [[ $MEMORY_GB != '' ]]; then
    echo "$SECTION_NAME: setting MEMORY to $MEMORY_GB GB"
    local memory_mb=$(( $MEMORY_GB * 1024 ))
    local memory_reservation_mb
    if [[ $MEMORY_RESERVATION_GB != '' ]]; then
        echo "$SECTION_NAME: setting MEMORY RESERVATION to $MEMORY_RESERVATION_GB GB"
        memory_reservation_mb=$(( $MEMORY_RESERVATION_GB * 1024 ))
    else
        echo "$SECTION_NAME: setting MEMORY RESERVATION to $MEMORY_GB GB"
        memory_reservation_mb=$memory_mb
    fi
    sed -i -e "s%<rasd:ElementName>24576MB of memory</rasd:ElementName>%<rasd:ElementName>${memory_mb}MB of memory</rasd:ElementName>%" \
        -e "s%<rasd:VirtualQuantity>24576</rasd:VirtualQuantity>%<rasd:VirtualQuantity>${memory_mb}</rasd:VirtualQuantity>%" \
        -e "s%<rasd:Reservation>24576</rasd:Reservation>%<rasd:Reservation>${memory_reservation_mb}</rasd:Reservation>%" $OVF || exit 5
  elif [[ $MEMORY_RESERVATION_GB != '' ]]; then
    echo "$SECTION_NAME: setting MEMORY RESERVATION to $MEMORY_RESERVATION_GB GB"
    local memory_reservation_mb=$(( $MEMORY_RESERVATION_GB * 1024 ))
    sed -i -e "s%<rasd:Reservation>24576</rasd:Reservation>%<rasd:Reservation>${memory_reservation_mb}</rasd:Reservation>%" $OVF || exit 5
  fi
  for MTU_VAR in GRID_NETWORK_MTU ADMIN_NETWORK_MTU CLIENT_NETWORK_MTU; do
    MTU_VALUE=$(eval echo \$${MTU_VAR})
    if [[ $MTU_VALUE != '' ]]; then
      echo "$SECTION_NAME: setting $MTU_VAR to $MTU_VALUE"
      sed -i "s/\(key=\"${MTU_VAR}\".*\)value=\"1400\"/\1value=\"${MTU_VALUE}\"/" $OVF || exit 5
    fi
  done

  ln -s "$VMDK" $TMP_DIR || exit 5
}

function add_storage
{
  local OVF_FILE=$1
  local DISK_VARS=$2
  local NODE_TYPE=$3
  local ORIG_OVF_FILE=$4

  # Remove default disk configuration (enclose in comment)
  sed -i -r -e "s/(<!-- @@DISK:DEFAULT_START@@) -->/\1/" \
            -e "s/<!-- (@@DISK:DEFAULT_END@@ -->)/\1/" \
            -e "s/(<!-- @@ITEM:DEFAULT_START@@) -->/\1/" \
            -e "s/<!-- (@@ITEM:DEFAULT_END@@ -->)/\1/"  "$OVF_FILE" || exit 5

  # Grab the last instanceID and first and last SCSI controller instanceIDs from the OVF_FILE
  local INSTANCEID=$(grep InstanceID "$OVF_FILE"| grep -v @@DISK:INSTANCEID@@| tail -1| grep -oP "(?<=>)[^<]*")
  local SCSI_CONTROLLER_ID=$(grep -A 1 '<rasd:ElementName>SCSI controller 0</rasd:ElementName>' $OVF_FILE |
               tail -1 | grep -oP "(?<=>)[^<]*")
  local SCSI_LAST_CONTROLLER_ID=$(grep -A 1 -P '<rasd:ElementName>SCSI controller \d+</rasd:ElementName>' $OVF_FILE |
               tail -1 | grep -oP "(?<=>)[^<]*")
  if [[ -z $SCSI_CONTROLLER_ID ]] || [[ -z $SCSI_LAST_CONTROLLER_ID ]]; then
    echo "Error: Can't determine SCSI controller instance IDs, file ($ORIG_OVF_FILE)" >&2
    exit 5
  fi

  # Start these at 1, to account for the root disk
  local DISK_COUNTER=1
  local DISK_ADDR=1
  local TOTAL_INSTANCES=0

  # Grab the "Disk" template line(s) from the ovf file
  OVF_DISK_TEMPLATE=$(sed -n -e '/<!-- @@DISK:ANCHOR@@/,/-->/{/@@DISK:ANCHOR@@/d;/-->/d;p;}' "$OVF_FILE")

  # Grab the "Item" template lines from the ovf file
  OVF_ITEM_TEMPLATE=$(sed -n -e '/<!-- @@ITEM:ANCHOR@@/,/-->/{/@@ITEM:ANCHOR@@/d;/-->/d;p;}' "$OVF_FILE")

  local IFS=$LF # Set field separator to LF
  for LINE in $DISK_VARS; do
    echo "$SECTION_NAME: overwriting default disk config with $LINE"

    # Grab INSTANCES and CAPACITY from the LINE
    local INSTANCES=$(echo $LINE| sed -n 's/.*INSTANCES *= *\([0-9]*\).*/\1/p')
    TOTAL_INSTANCES=$((TOTAL_INSTANCES+INSTANCES))
    case $NODE_TYPE in
      VM_Storage_Node)
        if [[ $INSTANCES -gt 256 ]]; then
          echo "Error: Maximum DISK INSTANCES for $NODE_TYPE type nodes is 256, section ${SECTION_NAME}" >&2
          exit 5
        fi
        ;;
      VM_Admin_Node)
        if [[ $TOTAL_INSTANCES -gt 2 ]]; then
          echo "Error: Admin nodes must have exactly 2 INSTANCES total, section ($SECTION_NAME)" >&2
          exit 5
        fi
        ;;
      *) # Should catch above in arg processing
        echo "Warning: DISK configuration is not supported for $NODE_TYPE type nodes, section ${SECTION_NAME}"
        ;;
    esac

    local CAPACITY=$(echo $LINE| sed -n 's/.*CAPACITY *= *\([0-9]*\).*/\1/p')

    # Loop over each instance
    local LOOP_COUNTER=1
    while [[ $LOOP_COUNTER -le $INSTANCES ]]; do

      # Sanity - should catch maximums in INSTANCES checks above
      if [[ $SCSI_CONTROLLER_ID -gt $SCSI_LAST_CONTROLLER_ID ]]; then
        echo "Error: Maximum disk count exceeded, section ${SECTION_NAME}" >&2
        exit 5
      fi

      local SED_CMD="sed"
      let INSTANCEID++

      # Create sed command to update ID, ADDRESSONPARENT, INSTANCEID, CAPACITY and ELEMENTNAME
      SED_CMD="$SED_CMD -e 's/@@DISK:ID@@/additional disk $DISK_COUNTER/'"
      SED_CMD="$SED_CMD -e 's/@@DISK:ADDRESSONPARENT@@/$DISK_ADDR/'"
      SED_CMD="$SED_CMD -e 's/@@DISK:PARENT@@/$SCSI_CONTROLLER_ID/'"
      SED_CMD="$SED_CMD -e 's/@@DISK:INSTANCEID@@/$INSTANCEID/'"
      SED_CMD="$SED_CMD -e 's/@@DISK:CAPACITY@@/$CAPACITY/'"
      SED_CMD="$SED_CMD -e 's/@@DISK:ELEMENTNAME@@/Hard disk $DISK_COUNTER/'"

      # The sed command at the end makes it a one-line string
      NEW_DISK_ENTRY=$(eval "echo '$OVF_DISK_TEMPLATE'| $SED_CMD| sed -e :a -e '\$!N; s/\\n/\\\\n/; ta'")
      NEW_ITEM_ENTRY=$(eval "echo '$OVF_ITEM_TEMPLATE'| $SED_CMD| sed -e :a -e '\$!N; s/\\n/\\\\n/; ta'")

      # Splice in the new disk entry
      sed -i -e "/@@DISK:ANCHOR@@/i $NEW_DISK_ENTRY" \
             -e "/@@ITEM:ANCHOR@@/i $NEW_ITEM_ENTRY" "$OVF_FILE" || exit 5

      let LOOP_COUNTER++
      let DISK_COUNTER++
      let DISK_ADDR++
      if [[ $DISK_ADDR -gt 6 ]]; then
        DISK_ADDR=0  # No root disk on subsequent controllers
        let SCSI_CONTROLLER_ID++
      fi
    done
  done
  if [[ $NODE_TYPE == VM_Admin_Node ]] && [[ $TOTAL_INSTANCES -ne 2 ]]; then
    echo "Error: Admin nodes must have exactly 2 INSTANCES total, section ($SECTION_NAME)" >&2
    exit 5
  fi
}

function update_manifest
{
  local OVF=$1
  local MANIFEST=${OVF/%.ovf/.mf}
  local SHA1SUM=$(sha1sum "$OVF"| awk '{print $1}'; test ${PIPESTATUS[0]} -eq 0) || exit 5
  local BASENAME=$(basename "$OVF")

  # Update the SHA1 entry as identified by BASENAME
  sed -i "s/SHA1($BASENAME)=[a-fA-F0-9]*$/SHA1($BASENAME)=$SHA1SUM/" $MANIFEST || exit 5
}

# Run the ovftool in the background
# Capture but do not stream the output, capture status and retry on failures
# For the purposes of running the command, it is enough to simply call:
# eval "$CMD"
function ovftool_bg
{
  local CMD=$1
  local NODE=$2
  local BANNER=$3

  local OUTPUT=''
  local STATUS=1
  local STATUS_TXT=
  local TRIES=0

  while [[ $STATUS != 0 && $TRIES -le $MAX_RETRIES ]]; do
    # IF this is a retry sleep, the vCenter may need to cleanup the failure
    [[ $TRIES -gt 0 ]] && sleep 10

    echo "Deploying $NODE" >&2
    OUTPUT=$(printf "$BANNER" "$NODE" "Beginning")
    OUTPUT="$OUTPUT$LF$(eval "$CMD")"
    STATUS=$?
    set_status_txt "$STATUS" "$OUTPUT"
    OUTPUT="$OUTPUT$LF$(printf "$BANNER" "$NODE" "$STATUS_TXT")$LF"
    let TRIES++
    echo "$OUTPUT"
  done
  # In case there were retries... Only capture the last attempt
  echo "$TRIES $STATUS_TXT $NODE" >> $SUMMARY_FILE
}

# Run the ovftool in the foreground
# Capture and stream the output, capture status and retry on failures
# For the purposes of running the command, it is enough to simply call:
# eval "$CMD"
function ovftool_fg
{
  local CMD=$1
  local NODE=$2
  local BANNER=$3

  local OUTPUT=''
  local STATUS=1
  local STATUS_TXT=
  local TRIES=0

  # Close file-device 5
  # (This should not hurt any parent process which may have used it)
  exec 5>&-
  # Duplicate STDOUT to file-device 5
  exec 5>&1

  while [[ $STATUS != 0 && $TRIES -le $MAX_RETRIES ]]; do
    # IF this is a retry sleep, the vCenter may need to cleanup the failure
    [[ $TRIES -gt 0 ]] && sleep 10

    echo "Deploying $NODE" >&2
    printf "$BANNER$LF" "$NODE" "Beginning"
    # Capture and stream the output at the same time
    # Also, ${PIPESTATUS[0]} has the exit status of (eval "$CMD")
    OUTPUT=$(eval "$CMD"| tee >(cat - >&5); test ${PIPESTATUS[0]} -eq 0)
    STATUS=$?
    set_status_txt "$STATUS" "$OUTPUT"
    printf "$BANNER$LF" "$NODE" "$STATUS_TXT"
    let TRIES++
  done

  # Close the file-descriptor
  exec 5>&-

  # In case there were retries... Only capture the last status
  echo "$TRIES $STATUS_TXT $NODE" >> $SUMMARY_FILE
}

function set_status_txt
{
  local STATUS=$1
  local OUTPUT=$2

  if [[ $STATUS -eq 0 ]]; then
      STATUS_TXT='Passed'
  else
    if [[ $(echo $OUTPUT| grep 'Transfer Completed'| wc -l) -gt 0 ]]; then
      STATUS_TXT='Deployed with errors'
    else
      STATUS_TXT='Failed'
    fi
  fi
}

function check_for_and_wait_for_bg_jobs
{
  local MAX_JOBS=$1
  local JOBS=$(jobs| wc -l)

  while [[ $JOBS -ge $MAX_JOBS ]]; do
    sleep 5
    # The extra execution of jobs does a refresh
    jobs > /dev/null
    JOBS=$(jobs| wc -l)
  done
}

function abort
{
  echo "${LF}Trapped CTRL-C... Killing any ovftool commands running in the background!" >&2
  # Gracefully kill the background processes
  JOB_IDS=$(jobs -pr| tr "$LF" " ")
  if [[ $JOB_IDS ]]; then
    echo "kill -INT $JOB_IDS"
    kill -INT $JOB_IDS
    sleep 5
    # If there are sill jobs, kill them abruptly
    JOB_IDS=$(jobs -pr| tr "$LF" " ")
    if [[ $JOB_IDS ]]; then
      echo "kill -9 $JOB_IDS"
      kill -9 $JOB_IDS
    fi
  fi
  TRAPPED='true'
  exit 3
}

function result_summary
{
  for TMP_DIR in ${TMP_DIRS[@]}; do
    if [[ $DONT_DELETE ]]; then
      echo "Not deleting directory: '$TMP_DIR'" >&2
    else
      rm -rf $TMP_DIR
    fi
  done

  EXIT_STATUS=${EXIT_STATUS:-4}
  if [[ -e $SUMMARY_FILE ]] && [[ $EXIT_STATUS -eq 4 ]]; then
    # Show the summary
    echo
    echo "Deployment Summary"
    echo "+-----------------------------+----------+----------------------+"
    echo "| node                        | attempts | status               |"
    echo "+-----------------------------+----------+----------------------+"
    SUMMARY="$(cat $SUMMARY_FILE)"
    echo "$SUMMARY"| while read -r ATTEMPTS RESULT NODE; do
      printf "| %-27s | %8s | %-20s |\n" "$NODE" "$ATTEMPTS" "$RESULT"
    done
    echo "+-----------------------------+----------+----------------------+"
    rm $SUMMARY_FILE

    # Calculate exit status
    if [[ $(echo "$SUMMARY"| grep -v 'Passed'| wc -l) -eq 0 ]]; then
      EXIT_STATUS=0
    elif [[ $(echo "$SUMMARY"| grep -v -e 'Passed' -e 'Deployed with errors'| wc -l) -eq 0 ]]; then
      EXIT_STATUS=1
    elif [[ $(echo "$SUMMARY"| grep -v -e 'Passed' -e 'Deployed with errors' -e 'Failed'| wc -l) -eq 0 ]]; then
      EXIT_STATUS=2
    else
      EXIT_STATUS=3
    fi
  fi

  # Unkwnow status if CTRL-C was hit (forced exit)
  if [[ $TRAPPED == 'true' ]]; then
    echo 'Deployment was interrupted via CTRL-C. Some instances of ovftool may have been killed!' >&2
    EXIT_STATUS=3
  fi

  if [[ $EXIT_STATUS == 0 ]] && [[ -n $RUN_ON_SUCCESS ]]; then
    echo "Successfull deployment of grid nodes."
    echo "Executing: $RUN_ON_SUCCESS"
    exec bash -xc "$RUN_ON_SUCCESS"
  fi

  exit $EXIT_STATUS
}

function process_cmd
{
  local CMD=$1
  local PREFIX=$2
  local SECTION_NAME=$3

  if [[ $NO_OP ]]; then
    echo
    echo "NOT Running: $CMD"
  else
    if [[ $DEBUG ]]; then
      echo "DEBUG ------------------ Command Start"
      echo "Command: $CMD"
      echo "DEBUG ------------------ Command End"
      echo
    fi
    if [[ $BACKGROUND ]]; then
      ovftool_bg "$PREFIX $CMD" "$SECTION_NAME" "################# %s %s ####################" "$SUMMARY_FILE" &
      # If we are maxed out on jobs, wait until something finishes
      check_for_and_wait_for_bg_jobs $MAX_JOBS
    else
      ovftool_fg "$PREFIX $CMD" "$SECTION_NAME" "################# %s %s ####################" "$SUMMARY_FILE"
    fi
  fi
}

trap result_summary EXIT

while getopts ':bDdhIi:j:np:r:S:s:t:u:xm:e:c:-:' OPT; do

  # Parse the long options
  # Retrofit them to use OPT and GETOPT
  if [[ $OPT == '-' ]]; then
    # Save the long option
    LONGOPT=$OPTARG
    # Grab first letter of the long option (almost works for all long options)
    OPT=${OPTARG:0:1}
    # Verify we received a valid long option
    case "$OPTARG" in
      # Parse the flag type options (no argument)
      background|debug|do-not-delete|help|ignore-ping|no-op)
        # Translate do-not-delete and ignore-ping (they are capitalized)
        if [[ $OPTARG == 'do-not-delete' ]]; then
          OPT=D
        elif [[ $OPTARG == 'ignore-ping' ]]; then
          OPT=I
        fi
        ;;
      # Parse the options with an additional argument
      cores|interactive|jobs|memory|memory-reservation|password|retries|single-node|source|target|username)
        # Translate single-node (it is capitalized)
        if [[ $OPTARG == 'single-node' ]]; then
          OPT=S
        # memory-reservation has short-form -e since -m is taken
        elif [[ $OPTARG == 'memory-reservation' ]]; then
          OPT=e
        fi
        # Overwrite OPTARG to be the next argument
        OPTARG=${!OPTIND}
        # Increment the option index to account for grabbing the argument
        let OPTIND++
        # Check that we have the additional argument
        if [[ $OPTARG == '' ]]; then
          echo "Option $LONGOPT requires an additional parameter." >&2
          exit 5
        fi
        ;;
      # Parse the options with an included argument
      cores=*|interactive=*|jobs=*|memory=*|memory-reservation=*|password=*|retries=*|single-node=*|source=*|target=*|username=*)
        # Translate single-node (it is capitalized)
        if [[ $OPTARG =~ ^'single-node=' ]]; then
          OPT=S
        # memory-reservation has short-form -e since -m is taken
        elif [[ $OPTARG =~ ^'memory-reservation' ]]; then
          OPT=e
        fi
        # Overwrite OPTARG to be everything after the equal sign
        OPTARG=${OPTARG#*=}
        # Check that we have the additional argument
        if [[ $OPTARG == '' ]]; then
          echo "Option $LONGOPT requires an additional parameter." >&2
          exit 5
        fi
        ;;
      *)
        if [[ $OPTERR -eq 1 ]]; then
          echo "Invalid option: --$OPTARG" >&2
          usage
        fi
        ;;
    esac
  fi

  # OPT and OPTARG now have the expected values for long-parsed options
  case $OPT in
    b)
      # Run ovftool in background
      BACKGROUND=1
      ;;
    c)
      GLOBAL_CORES=$OPTARG
      ;;
    D)
      # Do not delete temp dirs (leave ovf files behind)
      DONT_DELETE=1
      ;;
    d)
      # Enable debugging
      DEBUG=1
      ;;
    e)
      GLOBAL_MEMORY_RESERVATION_GB=$OPTARG
      ;;
    h)
      usage
      ;;
    I)
      IGNORE_PING=1
      ;;
    i)
      # Use interactive username/password prompting
      INTERACTIVE=$OPTARG
      if [[ $INTERACTIVE != once ]] && [[ $INTERACTIVE != all ]]; then
        echo "Interactive (-i) requires a value of 'once' or 'all'!" >&2
        usage
      fi
      ;;
    j)
      BACKGROUND=1
      MAX_JOBS=$OPTARG
      ;;
    m)
      GLOBAL_MEMORY_GB=$OPTARG
      ;;
    n)
      # Enable no-op (calls to ovftool are skipped)
      NO_OP=1
      ;;
    p)
      # Password provided at command prompt
      GLOBAL_PW=$OPTARG
      ;;
    r)
      MAX_RETRIES=$OPTARG
      ;;
    S)
      SINGLE_NODE=$OPTARG
      ;;
    s)
      # Source provided at command prompt
      GLOBAL_SOURCE=$OPTARG
      ;;
    t)
      # Target provided at command prompt
      GLOBAL_TARGET=$OPTARG
      ;;
    u)
      # Username provided at command prompt
      GLOBAL_UN=$OPTARG
      ;;
    x)
      echo "Option -x already applied" >/dev/null
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      usage
      ;;
  esac
done
# Remove all the options from the arguments
shift $((OPTIND-1))

# Config file should be remaining after parsing arguments
CONFIG_FILE=$1

# Error out if -b and -i were specified
if [[ $BACKGROUND ]] && [[ $INTERACTIVE == 'all' ]]; then
  echo "Interactive all '-i/--interactive all' is mutually exclusive with '-b'!" >&2
  exit 5
fi

# Usage requires a config-file
if [[ $CONFIG_FILE == '' ]]; then
  echo "No <config-file> specified!" >&2
  usage
fi
if [[ ! -f $CONFIG_FILE ]]; then
  echo "Config-file '$CONFIG_FILE' not found!" >&2
  usage
fi
echo "Using config file: $CONFIG_FILE"

# Check interactive option
if [[ $INTERACTIVE ]] && ([[ $GLOBAL_UN != '' ]] || [[ $GLOBAL_PW != '' ]]); then
  echo "Interactive (-i) is mutually exclusive with '-p' and '-u'!" >&2
  exit 5
fi

# Get global username and password interactively
if [[ $INTERACTIVE == once ]]; then
  while [[ $GLOBAL_UN == '' ]]; do
    echo -n "Enter global username: "
    read -r GLOBAL_UN
    if [[ $GLOBAL_UN == '' ]]; then
      echo "Please enter a valid username!" >&2
    fi
  done
  while [[ $GLOBAL_PW == '' ]]; do
    echo -n "Enter global password: "
    read -r -s GLOBAL_PW
    if [[ $GLOBAL_PW == '' ]]; then
      echo "Please enter a valid password!" >&2
    fi
    echo >&2
    echo >&2
  done
fi

validate_ini_format "$CONFIG_FILE"

# Remove extra white space, comments and blank lines
CONFIG_BLOB=$(sed -n -e "s/\s*=\s*/ = /" -e "s/^\s*//" -e "s/\s*$//" \
                  -e "1,\${/^\s*$/d;/^\s*[;#]/d;p;}" "$CONFIG_FILE")

# Isolate the Global vars block then remove "section" delimiter
GLOBAL_BLOCK=$(echo "$CONFIG_BLOB"| sed -n -e "1,/^\[/{/^\[/d;p;}")

[[ $DEBUG ]] && echo "DEBUG ------------------ Global Section Start"
[[ $DEBUG ]] && echo "$GLOBAL_BLOCK"
[[ $DEBUG ]] && echo "DEBUG ------------------ Global Section End"
[[ $DEBUG ]] && echo

# Flag to ensure only a single PA is defined in the config file
PRIMARY_ADMIN_SEEN=0

# Don't set the SIGINT trap until we enter the loop.  It causes
# problems if hit during password prompting above, and it isn't
# needed until we start firing off ovftool.
trap abort SIGINT

# Iterate through each block of config parameters
for I in $(echo "$CONFIG_BLOB"| awk '/^\[/ {printf "%i ", FNR}'); do

  SECTION_NAME=$(echo "$CONFIG_BLOB"| sed -n -e "s/\s*\[\s*//g" -e "s/\s*\]\s*//g" -e "$I,$I p")

  # If the --single-node argument was set, find the matching section
  [[ -n $SINGLE_NODE ]] && [[ $SINGLE_NODE != $SECTION_NAME ]] && continue

  # Isolate the block then remove "section" delimiter
  SECTION_BLOCK=$(echo "$CONFIG_BLOB"| sed -n -e "$I,/^\[/{/^\[/d;p;}")

  [[ $DEBUG ]] && echo "DEBUG ------------------ Section: $SECTION_NAME Starting at line: $I"
  [[ $DEBUG ]] && echo "$SECTION_BLOCK"
  [[ $DEBUG ]] && echo "DEBUG ------------------ Section End"
  [[ $DEBUG ]] && echo

  WHOLE_BLOCK=$SECTION_BLOCK
  apply_globals_to_whole_block "$GLOBAL_BLOCK"

  # Unset the variables prior to instantiate so they are undefined between iterations
  unset OVFTOOL_ARGUMENTS SOURCE TARGET USERNAME PASSWORD PROP_VARS DISK_VARS ADMIN_ROLE ADMIN_IP CORES MEMORY_GB MEMORY_RESERVATION_GB
  unset NET_VARS GRID_NETWORK_TARGET GRID_NETWORK_CONFIG GRID_NETWORK_IP GRID_NETWORK_MASK GRID_NETWORK_GATEWAY
  unset GRID_NETWORK_MTU ADMIN_NETWORK_ESL ADMIN_NETWORK_CONFIG ADMIN_NETWORK_TARGET ADMIN_NETWORK_IP ADMIN_NETWORK_MASK
  unset ADMIN_NETWORK_GATEWAY ADMIN_NETWORK_MTU CLIENT_NETWORK_CONFIG CLIENT_NETWORK_TARGET CLIENT_NETWORK_IP
  unset CLIENT_NETWORK_MASK CLIENT_NETWORK_GATEWAY CLIENT_NETWORK_MTU NODE_NAME UPDATE_MTU

  # Validate all key values as much as possible
  instantiate_vars "$WHOLE_BLOCK" "$SECTION_NAME"

  # Apply the global cores, memory_gb, and memory_reservation_gb (set via -c/-m/-e)
  CORES=${GLOBAL_CORES-$CORES}
  MEMORY_GB=${GLOBAL_MEMORY_GB-$MEMORY_GB}
  MEMORY_RESERVATION_GB=${GLOBAL_MEMORY_RESERVATION_GB-$MEMORY_RESERVATION_GB}

  # Apply the global source (set via -s)
  SOURCE=${GLOBAL_SOURCE-$SOURCE}
  if [[ -z $SOURCE  ]]; then
    SOURCE=$DEFAULT_SOURCE
  fi
  if [[ ! $SOURCE =~ 'http://' ]] && [[ ! $SOURCE =~ 'https://' ]]; then
    if [[ ! -d $SOURCE ]]; then
      echo "Error: Incorrect value for SOURCE." >&2
      echo "The value of SOURCE (-s) must be a directory or a URL to a directory." >&2
      exit 5
    fi
  fi

  # Apply the global target (set via -t)
  TARGET=${GLOBAL_TARGET-$TARGET}

  # Function set OVF, VMDK and MANIFEST variables
  verify_and_fetch_source "$SOURCE" "$NODE_TYPE" "$ADMIN_ROLE"

  # Any ovf modifications? e.g. add storage, change cores, change memory, update mtu
  if [[ "${DISK_VARS}${CORES}${MEMORY_GB}${MEMORY_RESERVATION_GB}${UPDATE_MTU}" != '' ]]; then

    OVF_ORIG=$OVF

    # Copy OVF to a tmp dir so we can modify it
    # Override CPU, memory and mtu during copy
    # Function updates OVF
    copy_source "$OVF" "$VMDK" "$MANIFEST"

    # Add storage to the ovf
    [[ $DISK_VARS ]] && add_storage "$OVF" "$DISK_VARS" "$NODE_TYPE" "$OVF_ORIG"

    # Update our copy of the manifest
    update_manifest "$OVF"
  fi

  # Escape each single quote (') with single and double quotes ('"'"')
  # The "eval" statement will reduce it back to a sigle quote
  OVF=${OVF//\'/\'\"\'\"\'}
  TARGET=${TARGET//\'/\'\"\'\"\'}

  # If global username and/or password was supplied, use them
  USERNAME=${GLOBAL_UN-$USERNAME}
  PASSWORD=${GLOBAL_PW-$PASSWORD}

  # Unset the username and password (let ovftool querey for credentials)
  # This assumes the vi:// target does not have them embedded
  if [[ $INTERACTIVE == all ]]; then
    unset USERNAME PASSWORD
  fi

  # Escape the one character (') that gets lost in the eval line below
  # All these other characters get passed along ~!@#$%^&*()_+{}|:"<>?`-=[]\;",./
  PASSWORD=${PASSWORD//\'/\'\"\'\"\'}

  # Ovftool requires encoding of the backslash (\) in the username
  USERNAME=${USERNAME//\\/%5C}

  if [[ $USERNAME != '' ]]; then
    # Inject the username into the target (never inject password)
    TARGET=${TARGET/vi:\/\//vi:\/\/$USERNAME@}
  else
    # If a password was supplied we must have a username
    if [[ $PASSWORD != '' ]]; then
      echo 'Error: A password was specified without specifying a username!' >&2
      exit 5
    fi
  fi

  # Ovftool requires encoding of the backslash (\) in the target
  TARGET=${TARGET//\\/%5C}

  # Since CMD will get evaluated, escape any single quotes
  VM_NAME=${SECTION_NAME//\'/\'\"\'\"\'}
  : ${NODE_NAME:=$VM_NAME}
  validate_node_name "$NODE_NAME"
  PROP_VARS="$PROP_VARS --prop:NODE_NAME='$NODE_NAME'"

  # The command we will execute (EULA prompts cause serious problems, so hardwire the override here)
  CMD="$OVFTOOL --acceptAllEulas $OVFTOOL_ARGUMENTS --name='$VM_NAME' $NET_VARS $PROP_VARS '$OVF' '$TARGET'"

  # Prefix a pipe of echo $PASSWORD
  if [[ $PASSWORD ]]; then
    #
    # Ovftool does not have a built-in secure manner to set the password,
    # so we pipe the password into ovftool's standard input.  If the we detect
    # that the SSL fingerprint needs to be accepted or the login credentials
    # are not valid (username being prompted again), exit the script.
    # NOTE: "echo" is built into bash so password is not exposed via "ps".
    #
    PREFIX="echo '$PASSWORD'|"

    # Verify access to this target with given username and password, if we haven't already
    if [[ -z $NO_OP ]] && [[ $PASSWORD != $PREV_PASSWORD ]] || [[ $TARGET != $PREV_TARGET ]]; then
      USERNAME_SEEN=''
      PREV_PASSWORD=$PASSWORD
      PREV_TARGET=$TARGET
      echo "Verifying ovftool login credentials for section '$SECTION_NAME'" >&2
      while read -r LINE; do
        if [[ $LINE =~ 'Accept SSL fingerprint' ]]; then
          echo "${LF}Error: SSL fingerprint validation required.  Run ovftool manually to accept SSL fingerprint." >&2
          echo "Example: $OVFTOOL '$TARGET'" >&2
          exit 5
        fi
        if [[ $LINE =~ 'Username' ]]; then
          if [[ -n $USERNAME_SEEN ]]; then
            echo "${LF}Error: Invalid ovftool login credentials for section '$SECTION_NAME'" >&2
            exit 5
          fi
          USERNAME_SEEN='true'
        fi
      done < <(eval "$PREFIX $OVFTOOL $OVFTOOL_ARGUMENTS '$TARGET'")
    fi
  fi

  # Create arrays for each command
  CMDS+=("$CMD")
  PREFIXES+=("$PREFIX")
  SECTION_NAMES+=("$SECTION_NAME")
done

# If the --single-node argument was set, make sure we found it
if [[ -n $SINGLE_NODE ]] && [[ $SINGLE_NODE != ${SECTION_NAMES[0]} ]]; then
  echo "${LF}Error: Could not find section ($SINGLE_NODE)!" >&2
  exit 5
fi

# Ping all the hosts unless --ignore-ping was specified or there are none (e.g. DHCP)
if [[ ${#PING_IPS[@]} -gt 0 ]] && [[ $IGNORE_PING -ne 1 ]]; then
  ping_ips "${PING_IPS[@]}"
fi

SUMMARY_FILE="/tmp/dvo-summary-$$.txt"

I=0
N=${#CMDS[@]}
# Iterate over all nodes
while [[ $I -lt $N ]]; do
  CMD="${CMDS[$I]}"
  PREFIX="${PREFIXES[$I]}"
  SECTION_NAME="${SECTION_NAMES[$I]}"

  if [[ "$CMD" =~ $PRIMARY_FILE ]] && [[ ! $BACKGROUND || $N -gt $MAX_JOBS ]]; then
    # Defer PA node
    PA_CMD="$CMD"
    PA_PREFIX="$PREFIX"
    PA_SECTION_NAME="$SECTION_NAME"
  else
    process_cmd "$CMD" "$PREFIX" "$SECTION_NAME"
  fi
  let I++
done

# If we deferred the PA, do it now.
if [[ $PA_CMD ]]; then
  process_cmd "$PA_CMD" "$PA_PREFIX" "$PA_SECTION_NAME"
fi

# Wait for all the ovftool instances to finish
check_for_and_wait_for_bg_jobs 1
