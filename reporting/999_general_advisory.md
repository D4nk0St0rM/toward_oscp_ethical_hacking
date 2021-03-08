#### Linux Based Systems

- Prevent transferring the exploit
  -Disable any services that could be used to transfer files to the target. These include:  FTP, TFTP, SMB, SCP, wget, and curl. Instead of removing and disabling such tools or services, another approach could be to limit access to them or to grant access only for specific accounts (so called ‘whitelisting’ where only those authorised are given access). While not infallible, such restrictions can prevent certain attacks or create sufficient obstacles that will force attackers into adopting less stealthy and more easily detectable methods. System administrators may also opt to monitor the usage of those tools for suspicious or malicious activity.
- Remove compilation tools
  - such as GCC, CC and other development tools. The general rule for compilation tools (and other tools that can be leveraged for an attack) is that they should only be installed if and for as long as you need them. If it’s really necessary to have compilation tools on your system, make sure that they can only available to specific user accounts. As mentioned earlier, this won’t prevent attackers from compiling exploits on a local system but we can attempt to prevent the attacker from transferring and executing the compiled exploit to the compromised host.
- Prevent exploit execution
  - limit writable and executable directories for system users and services. 
  - Attention should be paid to world-writable directories, such as the /tmp and /dev/shm directories. 
  - Creating separate partitions
    - improve the security of Linux systems by mounting directories such as /tmp and /home on a separated ‘noexec’ file system. 
    - binaries that are stored on these partitions cannot be executed by any user
- Limit the execution of existing applications for specific users
  - chmod 700 /executable/file
