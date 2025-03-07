#!/bin/bash

### Last Updated: March 6, 2025

scriptName="Token Escrow"
scriptVersion="2.0"
LOG_FILE="/var/log/bootstrap_escrow.log"

# Minimum version of swiftDialog required to use workflow
swiftDialogMinimumRequiredVersion="2.5.2"                     # Minimum version of swiftDialog required to use workflow
# Version of swiftDialog
dialogVersion=$( /usr/local/bin/dialog --version )
# Get the current major OS version
osVersion=$(/usr/bin/sw_vers -productVersion | /usr/bin/cut -d"." -f1)
osVersionFull=$(/usr/bin/sw_vers -productVersion)
osVersionExtra=$(/usr/bin/sw_vers -productVersionExtra)
osBuild=$( sw_vers -buildVersion )
osMajorVersion=$( echo "${osVersion}" | awk -F '.' '{print $1}' )
modelName=$( /usr/libexec/PlistBuddy -c 'Print :0:_items:0:machine_name' /dev/stdin <<< "$(system_profiler -xml SPHardwareDataType)" )

#echo "model name is $modelName"

# Report RSR sub-version if applicable
if [[ -n $osVersionExtra ]] && [[ "${osMajorVersion}" -ge 13 ]]; then osVersion="${osVersion} ${osVersionExtra}"; fi

# Function to log messages
log_message() {
    echo "${scriptName} ($scriptVersion):$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Create the log file if it does not exist
if [[ ! -f "${LOG_FILE}" ]]; then
    touch "${LOG_FILE}"
    if [[ -f "${LOG_FILE}" ]]; then
        log_message "Created specified LOG_FILE"
    else
        log_message "Unable to create specified LOG_FILE '${LOG_FILE}'; exiting.\n\n(Is this script running as 'root' ?)"
    fi
else
    log_message "Specified LOG_FILE exists; writing log entries to it"
fi
log_message "Starting Bootstrap Token escrow process."

### Overlay Icon ###
useOverlayIcon="true"
overlayicon=""
if [[ "$useOverlayIcon" == "true" ]]; then
    xxd -p -s 260 "$(defaults read /Library/Preferences/com.jamfsoftware.jamf self_service_app_path)"/Icon$'\r'/..namedfork/rsrc | xxd -r -p > /var/tmp/overlayicon.icns
    overlayicon="/var/tmp/overlayicon.icns"
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Validate / install swiftDialog (Thanks big bunches, @acodega!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Download swiftDialog
function dialogInstall() {

    # Get the URL of the latest PKG From the Dialog GitHub repo
    dialogURL=$(curl -L --silent --fail "https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")

    # Expected Team ID of the downloaded PKG
    expectedDialogTeamID="PWA5E9TQ59"

    log_message "Installing swiftDialog..."

    # Create temporary working directory
    workDirectory=$( /usr/bin/basename "$0" )
    tempDirectory=$( /usr/bin/mktemp -d "/private/tmp/$workDirectory.XXXXXX" )

    # Download the installer package
    /usr/bin/curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"

    # Verify the download
    teamID=$(/usr/sbin/spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')

    # Install the package if Team ID validates
    if [[ "$expectedDialogTeamID" == "$teamID" ]]; then
        /usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
        sleep 2
        dialogVersion=$( /usr/local/bin/dialog --version )
        log_message "swiftDialog version ${dialogVersion} installed; proceeding..."
    else
        # Display a so-called "simple" dialog if Team ID fails to validate
        infoOut "Unable to verify swift dialog team ID. Not installing or udpating"
    fi
    # Remove the temporary working directory when done
    /bin/rm -Rf "$tempDirectory"
}

# Check for dialog and install if it's not found
function dialogCheck() {

    # Set swiftDialogMinimumRequiredVersion based on osMajorVersion
    if [ "$osMajorVersion" -lt 12 ]; then
      swiftDialogMinimumRequiredVersion="2.4.2"
    else
      swiftDialogMinimumRequiredVersion="2.5.2"
    fi

    # Check for Dialog and install if not found
    if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]; then
        log_message "swiftDialog not found. Installing..."
        dialogInstall
    else
        dialogVersion=$(/usr/local/bin/dialog --version)
        if [[ "${dialogVersion}" < "${swiftDialogMinimumRequiredVersion}" ]]; then    
            log_message "swiftDialog version ${dialogVersion} found but swiftDialog ${swiftDialogMinimumRequiredVersion} or newer is required; updating..."
            dialogInstall
        else
        log_message "swiftDialog version ${dialogVersion} found; proceeding..."
        fi
    fi
}

# Check for dialog and install if it's not found
dialogCheck

# Function to handle dialog response codes
handle_dialog_response() {
    returncode=$1

    case ${returncode} in
        0)  # User clicked "Log Out"
            log_message "${CURRENT_USER} clicked Okay"
            ;;
        2|3)  # User clicked "Not Now" (button2 or info button)
            log_message "${CURRENT_USER} clicked Quit"
            exit "0"
            ;;
        4)  # Timer expired
            log_message "${CURRENT_USER} allowed timer to expire"
            exit "0"
            ;;
        5|10|30)  # User quit using cmd+Q, command file quit, or authentication failed
            log_message "${CURRENT_USER} quit or authentication failed"
            exit "0"
            ;;
        *)  # Unexpected return code
            log_message "Unexpected return code: ${returncode}"
            exit "${returncode}"
            ;;
    esac
}

### Preparing for failover
CURRENT_USER_ALIAS=$(/bin/echo "show State:/Users/ConsoleUser" | /usr/sbin/scutil | /usr/bin/awk '/Name :/&&!/loginwindow/{print $3}')
CURRENT_USER=$(id -un "$CURRENT_USER_ALIAS")

USER_ID=$(/usr/bin/id -u "$CURRENT_USER")
if [[ "$OS_MAJOR" -eq 10 && "$OS_MINOR" -le 9 ]]; then
    L_ID=$(/usr/bin/pgrep -x -u "$USER_ID" loginwindow)
    L_METHOD="bsexec"
else
    L_ID=$USER_ID
    L_METHOD="asuser"
fi

AllUsers=$(dscl . list /Users | grep -v _)
for EachUser in $AllUsers; do
    
    TokenValue=$(sysadminctl -secureTokenStatus $EachUser 2>&1)
    log_message "Checking $EachUser"
	dseditgroup -o edit -a "$EachUser" -t user admin

    if [[ $TokenValue = *"ENABLED"* ]]; then
        SecureTokenUsers+=($EachUser,)
    fi
done

# Prepare the list of selectable options for Swift Dialog
options=""
for user in $SecureTokenUsers; do
    options="$options|$user"
done
options="$options|Select User"
# Remove the first "|" character from the options string
options=${SecureTokenUsers[@]}
remove_commas=$(echo "${SecureTokenUsers[@]}" | sed 's/\(.*\),/\1/')
firstuser=$(echo "${SecureTokenUsers[@]}" | sed 's/\(.*\),/\1/' | awk '{print $1}')
log_message "Options are: ${remove_commas}"
# Display the Swift Dialog window with selectable options
selected_user=$( dialog --title "Escrow Bootstrap Token" --icon /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/UserIcon.icns --overlayicon $overlayicon --message "Please select a username for which a password is known. \n\nYou will be asked to provide the password on the next screen." --selecttitle "Username" --selectvalues "$remove_commas" --ontop --moveable --small --timer "300" --hidetimerbar --quitoninfo --infobuttontext "Quit")

# Handle the dialog response
handle_dialog_response "$?"

username=$(echo $selected_user | awk -F " " '{print $3}' | tr -d '"')
log_message "Username chosen is: ${username}"

selected_user=$(dialog --title "Escrow Bootstrap Token" --icon /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/UserIcon.icns --overlayicon $overlayicon --message "Please provide the password for \n\n • **$username**" --textfield "Password",secure,required --ontop --moveable --small --timer "300" --hidetimerbar --quitoninfo --infobuttontext "Quit")

# Handle the dialog response
handle_dialog_response "$?"

password=$(echo $selected_user | awk -F " : " '{print $NF}')
#echo "Password chosen is:" $password
#echo "___________"
#echo "Selected user info: $selected_user"
#echo "___________"

# Check if the user made a selection and display the result
if [ "$selected_user" == "" ]; then
    log_message "No user was selected."
else
    log_message "$username Selected"
    
fi

TRY=1
    until /usr/bin/dscl /Search -authonly "$username" "$password" &>/dev/null; do
    (( TRY++ ))
    log_message "Prompting $username for their Mac password (attempt $TRY)..."
    
    USER_PASS=$(dialog --title "Try again" \
        --icon /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns \
        --overlayicon $overlayicon \
        --message "The password entered for **$username** was incorrect. \n\nPlease try again.\n\n(Attempt $TRY/5)" \
        --textfield "Password",secure,required \
        --ontop --moveable --small --quitoninfo --infobuttontext "Quit" --timer "300" --hidetimerbar)

        # Handle the dialog response
        handle_dialog_response "$?"

    password=$(echo "$USER_PASS" | awk -F " : " '{print $NF}')
    
    if (( TRY >= 5 )); then
        log_message "[ERROR] Password prompt unsuccessful after 5 attempts. Displaying failure message..."
        dialog --title "Unable to escrow" \
            --icon /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns \
            --overlayicon $overlayicon \
            --message "The passwords provided for username \n\n • **$username** are not valid. \n\nPlease try again later or contact Technology Services for assistance." \
            --ontop --moveable --small --quitoninfo --infobuttontext "Quit" --timer "300" --hidetimerbar

            # Handle the dialog response
            handle_dialog_response "$?"

        exit 1
    fi
done

log_message "[SUCCESS] Password verified for $username. Proceeding to escrow Bootstrap Token."

# **Show Confirmation Dialog Before Proceeding**
dialog --title "Password Verified" \
    --icon SF=icloud.and.arrow.up.fill,weight=bold \
    --overlayicon $overlayicon \
    --message "The password for **$username** has been verified successfully. \n\nThe system will now attempt to escrow the Bootstrap Token after the timer expires or you can click **OK**." \
    --ontop --moveable --small --timer "30" --button1text "OK"

log_message "Escrowing Bootstrap Token for $username..."

# Handle the dialog response
handle_dialog_response "$?"

ESCROW_SCRIPT="/Library/Application Support/JAMF/tmp/escrowToken"
log_message "Creating Escrow Script for $username at $ESCROW_SCRIPT..."
# Create expect script for bootstraptoken escrow
cat << EOP > "$ESCROW_SCRIPT"
#! /usr/bin/expect -f

set username "[lindex \$argv 0]"
set password "[lindex \$argv 1]"

spawn /usr/bin/profiles install -type bootstraptoken
expect {
    "Enter the admin user name:" { send "\$username\r" }
    timeout { exit 1 }
}

expect {
    "Enter the password for user '\$username':" { send "\$password\r" }
    timeout { exit 2 }
}

expect {
    "profiles: Bootstrap Token escrowed successfully" {
        exit 0
    }
    timeout { exit 3 }
}

EOP

chmod +x "$ESCROW_SCRIPT"
"$ESCROW_SCRIPT" "$username" "$password"
EXIT_CODE=$?

log_message "Escrow Script completed with exit code $EXIT_CODE."

if [[ $EXIT_CODE -eq 0 ]]; then
    log_message "[SUCCESS] Bootstrap Token escrowed successfully for $username."
    
    # Show Success Dialog
    dialog --title "Bootstrap Token Escrowed" \
        --icon SF=checkmark.circle.fill,weight=bold,colour1=#00ff44,colour2=#075c1e \
        --overlayicon $overlayicon \
        --message "The Bootstrap Token was successfully escrowed for **$username**. \n\nWe will now update the device inventory to Jamf Pro. \n\nYou can now close this window." \
        --button1text "OK" --ontop --moveable --small --timer "60" --hidetimerbar --quitoninfo --infobuttontext "Quit"

    # Handle the dialog response
    handle_dialog_response "$?"
else
    log_message "[ERROR] Bootstrap Token escrow failed for $username with exit code $EXIT_CODE."

    # Show Failure Dialog
    dialog --title "Bootstrap Token Escrow Failed" \
        --icon /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns \
        --overlayicon $overlayicon \
        --message "There was an issue escrowing the Bootstrap Token for **$username**.\n\nPlease try again or contact IT support." \
        --button1text "OK" --ontop --moveable --small --timer "60" --hidetimerbar --quitoninfo --infobuttontext "Quit"
    
    # Handle the dialog response
    handle_dialog_response "$?"
fi

# Remove Escrow Script
log_message "Pausing for 3 seconds before Removing Escrow Script..."
sleep 3

# Remove Escrow Script
log_message "Removing Escrow Script..."
rm -f "$ESCROW_SCRIPT"

# Pause for 3 seconds before recon
log_message "Pausing for 3 seconds before recon..."
sleep 3

# Run Recon
log_message "Running recon..."
jamf recon

exit 0