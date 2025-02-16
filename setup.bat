@echo off
echo Setting up repository structure...

REM Create directory structure
md scripts 2>nul
md docs 2>nul
md docs\templates 2>nul
md examples 2>nul
md examples\config 2>nul
md .github 2>nul
md .github\workflows 2>nul
md .github\ISSUE_TEMPLATE 2>nul

REM Move script files to scripts directory
move /Y harden.sh scripts\ 2>nul
move /Y setup-2fa.sh scripts\ 2>nul
move /Y setup-ssh-key.sh scripts\ 2>nul
move /Y setup.sh scripts\ 2>nul
move /Y create-admin.sh scripts\ 2>nul

REM Move documentation to docs
move /Y GUIDE.md docs\ 2>nul
move /Y recovery-procedures.md docs\ 2>nul
move /Y system-configuration.md docs\ 2>nul

REM Create example configuration
echo # Example configuration > examples\config\hardening.conf.example
echo SSH_PORT="3333" >> examples\config\hardening.conf.example
echo SSH_ALLOW_USERS="admin" >> examples\config\hardening.conf.example
echo FIREWALL_ADDITIONAL_PORTS="80,443" >> examples\config\hardening.conf.example

REM Initialize git repository if not already initialized
if not exist .git (
    echo Initializing git repository...
    git init
    git add .
    git commit -m "Initial commit: Ubuntu Server Hardening Scripts"
)

echo.
echo Repository structure set up successfully!
echo.
echo Next steps:
echo 1. Create a new repository at https://github.com/amraly83/hardening-ubuntu
echo 2. Run these commands to push your code:
echo    git remote add origin https://github.com/amraly83/hardening-ubuntu.git
echo    git push -u origin master
echo.
pause