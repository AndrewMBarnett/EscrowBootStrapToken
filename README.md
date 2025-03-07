# **Bootstrap Token Escrow Script**  

## **Overview**  
This script facilitates the escrow of a Bootstrap Token on macOS devices, ensuring proper security and management capabilities within a Jamf-managed environment. The script uses **SwiftDialog** to provide a user-friendly interface for selecting a Secure Token-enabled user and authenticating with their credentials.  

## **Features**  
- **SwiftDialog Integration** – Provides a guided user experience for authentication.  
- **Secure Token Detection** – Identifies and lists users with Secure Token access.  
- **Bootstrap Token Escrow** – Automates the process of storing the Bootstrap Token using `profiles install -type bootstraptoken`.  
- **Error Handling & Logging** – Captures user interactions, authentication attempts, and escrow results in a log file (`/var/log/bootstrap_escrow.log`).  
- **User Quit Handling** – Allows users to exit at any stage, ensuring the script does not continue unnecessarily.  

## **Requirements**  
- **Jamf Pro** – The script can be deployed via Jamf Pro for automated execution.  
- **SwiftDialog** – Used for interactive user prompts.  
- **macOS 10.15+** – Required for Bootstrap Token support.  

## **Usage**  
1. **Deploy via Jamf Pro** or run locally as an admin.  
2. **Follow on-screen prompts** to select a Secure Token-enabled user.  
3. **Enter the user’s password** when prompted.  
4. **Upon successful authentication**, the Bootstrap Token is escrowed to Jamf.  
5. **A confirmation message** will indicate success or failure.  

## **Logging & Troubleshooting**  
- All actions and authentication attempts are logged in `/var/log/bootstrap_escrow.log`.  
- If a user quits, the script will exit without further attempts.  
- If authentication fails five times, the process will terminate with an error message.  

## **Support**  
For issues or improvements, feel free to submit a GitHub issue or reach out to IT support.  
